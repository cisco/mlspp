#include "session.h"
#include "common.h"
#include "state.h"

namespace mls {

std::tuple<Session, Welcome>
Session::start(const bytes& group_id,
               const std::vector<ClientInitKey>& my_client_init_keys,
               const std::vector<ClientInitKey>& client_init_keys,
               const bytes& initial_secret)
{
  auto [welcome, state] = State::negotiate(
    group_id, my_client_init_keys, client_init_keys, initial_secret);

  Session session;
  session.add_state(0, state);
  return std::make_tuple(session, welcome);
}

Session
Session::join(const std::vector<ClientInitKey>& client_init_keys,
              const Welcome& welcome)
{
  Session session;
  State next(client_init_keys, welcome);
  session.add_state(0, next);
  return session;
}

std::tuple<Welcome, bytes>
Session::add(const bytes& add_secret, const ClientInitKey& client_init_key)
{
  auto proposal = current_state().add(client_init_key);
  return commit_and_cache(add_secret, proposal);
}

bytes
Session::update(const bytes& leaf_secret)
{
  auto proposal = current_state().update(leaf_secret);
  return std::get<1>(commit_and_cache(leaf_secret, proposal));
}

bytes
Session::remove(const bytes& evict_secret, uint32_t index)
{
  auto proposal = current_state().remove(LeafIndex{ index });
  return std::get<1>(commit_and_cache(evict_secret, proposal));
}

std::tuple<Welcome, bytes>
Session::commit_and_cache(const bytes& secret, const MLSPlaintext& proposal)
{
  auto state = current_state();
  state.handle(proposal);
  auto [commit, welcome, new_state] = state.commit(secret);

  tls::ostream w;
  w << proposal << commit;
  auto msg = w.bytes();

  _outbound_cache = std::make_tuple(msg, new_state);
  return std::make_tuple(welcome, msg);
}

void
Session::handle(const bytes& handshake_data)
{
  auto suite = current_state().cipher_suite();
  MLSPlaintext proposal(suite), commit(suite);
  tls::istream r(handshake_data);
  r >> proposal >> commit;

  if (proposal.sender == current_state().index()) {
    if (!_outbound_cache.has_value()) {
      throw ProtocolError("Received from self without sending");
    }

    auto message = std::get<0>(_outbound_cache.value());
    auto state = std::get<1>(_outbound_cache.value());

    if (message != handshake_data) {
      throw ProtocolError("Received different own message");
    }

    add_state(proposal.epoch, state);
    _outbound_cache = std::nullopt;
    return;
  }

  auto state = current_state();
  state.handle(proposal);
  auto next = state.handle(commit);
  if (!next.has_value()) {
    throw ProtocolError("Commit failed to produce a new state");
  }

  add_state(commit.epoch, next.value());
}

bytes
Session::protect(const bytes& plaintext)
{
  auto ciphertext = current_state().protect(plaintext);
  return tls::marshal(ciphertext);
}

// TODO(rlb@ipv.sx): It would be good to expose identity information
// here, since ciphertexts are authenticated per sender.  Who sent
// this ciphertext?
bytes
Session::unprotect(const bytes& ciphertext)
{
  auto ciphertext_obj = tls::get<MLSCiphertext>(ciphertext);
  if (_state.count(ciphertext_obj.epoch) == 0) {
    throw MissingStateError("No state available to decrypt ciphertext");
  }

  auto& state = _state.at(ciphertext_obj.epoch);
  return state.unprotect(ciphertext_obj);
}

void
Session::add_state(epoch_t prior_epoch, const State& state)
{
  // XXX(rlb@ipv.sx) Assumes no epoch collisions, which is clearly
  // not the case with the current linear updating.
  _state.emplace(state.epoch(), state);

  // XXX(rlb@ipv.sx) First successor updates the head pointer
  if (prior_epoch == _current_epoch || _state.size() == 1) {
    _current_epoch = state.epoch();
  }
}

const State&
Session::current_state() const
{
  if (_state.count(_current_epoch) == 0) {
    throw MissingStateError("No state available for current epoch");
  }

  return _state.at(_current_epoch);
}

State&
Session::current_state()
{
  if (_state.count(_current_epoch) == 0) {
    throw MissingStateError("No state available for current epoch");
  }

  return _state.at(_current_epoch);
}

bool
operator==(const Session& lhs, const Session& rhs)
{
  if (lhs._current_epoch != rhs._current_epoch) {
    return false;
  }

  for (const auto& pair : lhs._state) {
    if (rhs._state.count(pair.first) == 0) {
      continue;
    }

    if (rhs._state.at(pair.first) != pair.second) {
      return false;
    }
  }

  return true;
}

bool
operator!=(const Session& lhs, const Session& rhs)
{
  return !(lhs == rhs);
}

} // namespace mls
