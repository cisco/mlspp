#include "mls/session.h"
#include "mls/common.h"
#include "mls/state.h"

namespace mls {

///
/// Client
///

Client::Client(CipherSuite suite_in, SignaturePrivateKey sig_priv_in, Credential cred_in)
  : suite(suite_in)
  , sig_priv(std::move(sig_priv_in))
  , cred(std::move(cred_in))
{}

Session
Client::begin_session(const bytes& group_id) const
{
  auto init_priv = HPKEPrivateKey::generate(suite);
  auto kp = KeyPackage{ suite, init_priv.public_key, cred, sig_priv };
  return Session::begin(group_id, init_priv, sig_priv, kp);
}

PendingJoin
Client::start_join() const
{
  return PendingJoin(suite, sig_priv, cred);
}

///
/// PendingJoin
///

PendingJoin::PendingJoin(CipherSuite suite_in, SignaturePrivateKey sig_priv_in, Credential cred_in)
  : suite(suite_in)
  , init_priv(HPKEPrivateKey::generate(suite))
  , sig_priv(std::move(sig_priv_in))
  , key_package_inner(suite, init_priv.public_key, cred_in, sig_priv)
{}

bytes
PendingJoin::key_package() const
{
  return tls::marshal(key_package_inner);
}

Session
PendingJoin::complete(const bytes& welcome) const
{
  return Session::join(init_priv, sig_priv, key_package_inner, welcome);
}

///
/// Session
///

Session::Session()
  : _current_epoch(0)
  , _encrypt_handshake(false)
{}

Session
Session::begin(const bytes& group_id,
               const HPKEPrivateKey& init_priv,
               const SignaturePrivateKey& sig_priv,
               const KeyPackage& key_package)
{
  Session session;
  session.add_state(0, { group_id, key_package.cipher_suite, init_priv, sig_priv, key_package });
  return session;
}

Session
Session::join(const HPKEPrivateKey& init_priv,
              const SignaturePrivateKey& sig_priv,
              const KeyPackage& key_package,
              const bytes& welcome_data)
{
  auto welcome = tls::get<Welcome>(welcome_data);

  Session session;
  session.add_state(0, { init_priv, sig_priv, key_package, welcome });
  return session;
}

void
Session::encrypt_handshake(bool enabled)
{
  _encrypt_handshake = enabled;
}

bytes
Session::add(const bytes& key_package_data)
{
  auto key_package = tls::get<KeyPackage>(key_package_data);
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

    add_state(handshake.epoch, next_state);
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
