#include "mls/session.h"
#include "mls/common.h"
#include "mls/state.h"

namespace mls {

Session::InitInfo::InitInfo(HPKEPrivateKey init_priv_in,
                            SignaturePrivateKey sig_priv_in,
                            KeyPackage key_package_in)
  : init_priv(std::move(init_priv_in))
  , sig_priv(std::move(sig_priv_in))
  , key_package(std::move(key_package_in))
{
  if (init_priv.public_key != key_package.init_key) {
    throw InvalidParameterError("Init key mismatch");
  }

  if (sig_priv.public_key != key_package.credential.public_key()) {
    throw InvalidParameterError("Signature key mismatch");
  }
}

Session::Session()
  : _current_epoch(0)
  , _encrypt_handshake(false)
{}

std::tuple<Session, bytes>
Session::start(const bytes& group_id,
               const std::vector<InitInfo>& my_info,
               const std::vector<KeyPackage>& key_packages)
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

  const auto suite = my_selected_info->key_package.cipher_suite;
  const auto& init_priv = my_selected_info->init_priv;
  const auto& sig_priv = my_selected_info->sig_priv;
  const auto& kp = my_selected_info->key_package;

  auto commit_secret = random_bytes(32); // XXX(RLB) stopgap until method removed
  auto init_state = State{ group_id, suite, init_priv, sig_priv, kp };
  auto add = init_state.add(*other_selected_kp);
  init_state.handle(add);
  auto [unused_commit, welcome, state] = init_state.commit(commit_secret);
  silence_unused(unused_commit);

  Session session;
  session.add_state(0, state);
  return std::make_tuple(session, tls::marshal(welcome));
}

Session
Session::join(const std::vector<InitInfo>& my_info, const bytes& welcome_data)
{
  auto welcome = tls::get<Welcome>(welcome_data);

  Session session;
  for (const auto& info : my_info) {
    auto maybe_kpi = welcome.find(info.key_package);
    if (!maybe_kpi.has_value()) {
      continue;
    }

    session.add_state(
      0, { info.init_priv, info.sig_priv, info.key_package, welcome });
    return session;
  }

  throw InvalidParameterError("No matching KeyPackage found");
}

void
Session::encrypt_handshake(bool enabled)
{
  _encrypt_handshake = enabled;
}

bytes
Session::add(const KeyPackage& key_package)
{
  auto proposal = current_state().add(key_package);
  return export_message(proposal);
}

bytes
Session::update()
{
  auto leaf_secret = fresh_secret();
  auto proposal = current_state().update(leaf_secret);
  return export_message(proposal);
}

bytes
Session::remove(uint32_t index)
{
  auto proposal = current_state().remove(LeafIndex{ index });
  return export_message(proposal);
}

std::tuple<bytes, bytes>
Session::commit()
{
  auto commit_secret = fresh_secret();
  auto [commit, welcome, new_state] = current_state().commit(commit_secret);

  auto commit_msg = export_message(commit);
  auto welcome_msg = tls::marshal(welcome);

  _outbound_cache = std::make_tuple(commit_msg, new_state);
  return std::make_tuple(welcome_msg, commit_msg);
}

bytes
Session::fresh_secret() const
{
  const auto suite = current_state().cipher_suite();
  const auto secret_size = suite.get().hpke.kdf.hash_size();
  return random_bytes(secret_size);
}

bytes
Session::export_message(const MLSPlaintext& plaintext)
{
  if (!_encrypt_handshake) {
    return tls::marshal(plaintext);
  }

  auto ciphertext = current_state().encrypt(plaintext);
  return tls::marshal(ciphertext);
}

MLSPlaintext
Session::import_message(const bytes& encoded)
{
  if (!_encrypt_handshake) {
    return tls::get<MLSPlaintext>(encoded);
  }

  auto ciphertext = tls::get<MLSCiphertext>(encoded);
  return current_state().decrypt(ciphertext);
}

bool
Session::handle(const bytes& handshake_data)
{
  auto handshake = import_message(handshake_data);

  if (handshake.sender.sender_type != SenderType::member) {
    throw ProtocolError("External senders not supported");
  }

  auto is_commit = std::holds_alternative<CommitData>(handshake.content);
  if (is_commit &&
      LeafIndex(handshake.sender.sender) == current_state().index()) {
    if (!_outbound_cache.has_value()) {
      throw ProtocolError("Received from self without sending");
    }

    const auto& cached_msg = std::get<0>(_outbound_cache.value());
    const auto& next_state = std::get<1>(_outbound_cache.value());
    if (cached_msg != handshake_data) {
      throw ProtocolError("Received message different from cached");
    }

    add_state(current_state().epoch(), next_state);
    _outbound_cache = std::nullopt;
    return true;
  }

  auto maybe_next_state = current_state().handle(handshake);
  if (!maybe_next_state.has_value()) {
    return false;
  }

  add_state(handshake.epoch, maybe_next_state.value());
  return true;
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
