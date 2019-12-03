#include "session.h"
#include "common.h"
#include "state.h"

namespace mls {

std::tuple<Session, Welcome, bytes>
Session::start(const bytes& group_id,
               const std::vector<ClientInitKey>& my_client_init_keys,
               const std::vector<ClientInitKey>& client_init_keys)
{
  auto welcome_add_state =
    State::negotiate(group_id, my_client_init_keys, client_init_keys);

  Session session;
  session.add_state(0, std::get<2>(welcome_add_state));
  auto welcome = std::get<0>(welcome_add_state);
  auto add = tls::marshal(std::get<1>(welcome_add_state));
  return std::make_tuple(session, welcome, add);
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

std::pair<Welcome, bytes>
Session::add(const ClientInitKey& client_init_key)
{
  auto welcome_add_state = current_state().add(client_init_key);
  auto welcome = std::get<0>(welcome_add_state);
  auto add = tls::marshal(std::get<1>(welcome_add_state));
  auto state = std::get<2>(welcome_add_state);

  _outbound_cache = std::make_tuple(add, state);

  return std::make_pair(welcome, add);
}

bytes
Session::update(const bytes& leaf_secret)
{
  auto update_state = current_state().update(leaf_secret);
  auto update = tls::marshal(std::get<0>(update_state));
  auto state = std::get<1>(update_state);

  _outbound_cache = std::make_tuple(update, state);

  return update;
}

bytes
Session::remove(const bytes& evict_secret, uint32_t index)
{
  auto remove_state = current_state().remove(evict_secret, LeafIndex{ index });
  auto remove = tls::marshal(std::get<0>(remove_state));
  auto state = std::get<1>(remove_state);

  _outbound_cache = std::make_tuple(remove, state);

  return remove;
}

void
Session::handle(const bytes& handshake_data)
{
  auto handshake =
    tls::get<MLSPlaintext>(handshake_data, current_state().cipher_suite());

  if (handshake.sender == current_state().index()) {
    if (!_outbound_cache.has_value()) {
      throw ProtocolError("Received from self without sending");
    }

    auto message = std::get<0>(_outbound_cache.value());
    auto state = std::get<1>(_outbound_cache.value());

    if (message != handshake_data) {
      throw ProtocolError("Received different own message");
    }

    add_state(handshake.epoch, state);
    _outbound_cache = std::nullopt;
    return;
  }

  auto next = current_state().handle(handshake);
  add_state(handshake.epoch, next);
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
