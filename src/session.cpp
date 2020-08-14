#include "mls/session.h"
#include "mls/common.h"
#include "mls/state.h"

namespace mls {

Session::InitInfo::InitInfo(bytes init_secret_in,
                            SignaturePrivateKey sig_priv_in,
                            KeyPackage key_package_in)
  : init_secret(std::move(init_secret_in))
  , sig_priv(std::move(sig_priv_in))
  , key_package(std::move(key_package_in))
{
  auto init_priv =
    HPKEPrivateKey::derive(key_package.cipher_suite, init_secret);
  if (init_priv.public_key() != key_package.init_key) {
    throw InvalidParameterError("Init key mismatch");
  }

  if (sig_priv.public_key() != key_package.credential.public_key()) {
    throw InvalidParameterError("Signature key mismatch");
  }
}

Session::Session()
  : _current_epoch(0)
  , _encrypt_handshake(false)
{}

std::tuple<Session, Welcome>
Session::start(const bytes& group_id,
               const std::vector<InitInfo>& my_info,
               const std::vector<KeyPackage>& key_packages,
               const bytes& initial_secret)
{
  // Negotiate a ciphersuite with the other party
  auto selected = false;
  const InitInfo* my_selected_info = nullptr;
  const KeyPackage* other_selected_kp = nullptr;
  for (const auto& info : my_info) {
    for (const auto& other_kp : key_packages) {
      if (info.key_package.cipher_suite == other_kp.cipher_suite) {
        selected = true;
        my_selected_info = &info;
        other_selected_kp = &other_kp;
        break;
      }
    }

    if (selected) {
      break;
    }
  }

  if (!selected) {
    throw ProtocolError("Negotiation failure");
  }

  auto& suite = my_selected_info->key_package.cipher_suite;
  auto& init_secret = my_selected_info->init_secret;
  auto& sig_priv = my_selected_info->sig_priv;
  auto& kp = my_selected_info->key_package;

  auto init_state = State{ group_id, suite, init_secret, sig_priv, kp };
  auto add = init_state.add(*other_selected_kp);
  init_state.handle(add);
  auto [unused_commit, welcome, state] = init_state.commit(initial_secret);
  silence_unused(unused_commit);

  Session session;
  session.add_state(0, state);
  return std::make_tuple(session, welcome);
}

Session
Session::join(const std::vector<InitInfo>& my_info, const Welcome& welcome)
{
  Session session;
  for (const auto& info : my_info) {
    auto maybe_kpi = welcome.find(info.key_package);
    if (!maybe_kpi.has_value()) {
      continue;
    }

    session.add_state(
      0, { info.init_secret, info.sig_priv, info.key_package, welcome });
    return session;
  }

  throw InvalidParameterError("No matching KeyPackage found");
}

void
Session::encrypt_handshake(bool enabled)
{
  _encrypt_handshake = enabled;
}

std::tuple<Welcome, bytes>
Session::add(const bytes& add_secret, const KeyPackage& key_package)
{
  auto proposal = current_state().add(key_package);
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
  if (_encrypt_handshake) {
    auto enc_proposal = state.encrypt(proposal);
    auto enc_commit = state.encrypt(commit);
    w << enc_proposal << enc_commit;
  } else {
    w << proposal << commit;
  }
  auto msg = w.bytes();

  _outbound_cache = std::make_tuple(msg, new_state);
  return std::make_tuple(welcome, msg);
}

void
Session::handle(const bytes& handshake_data)
{
  auto& state = current_state();
  MLSPlaintext proposal, commit;
  tls::istream r(handshake_data);
  if (_encrypt_handshake) {
    // TODO(rlb): Verify that epoch of the ciphertext matches that of the
    // current state
    MLSCiphertext enc_proposal, enc_commit;
    r >> enc_proposal >> enc_commit;
    proposal = state.decrypt(enc_proposal);
    commit = state.decrypt(enc_commit);
  } else {
    r >> proposal >> commit;
  }

  if (proposal.sender.sender_type != SenderType::member) {
    throw ProtocolError("External senders not supported");
  }

  if (LeafIndex(proposal.sender.sender) == current_state().index()) {
    if (!_outbound_cache.has_value()) {
      throw ProtocolError("Received from self without sending");
    }

    auto message = std::get<0>(_outbound_cache.value());
    auto next_state = std::get<1>(_outbound_cache.value());

    if (message != handshake_data) {
      throw ProtocolError("Received different own message");
    }

    add_state(proposal.epoch, next_state);
    _outbound_cache = std::nullopt;
    return;
  }

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
  if (lhs._encrypt_handshake != rhs._encrypt_handshake) {
    return false;
  }

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
