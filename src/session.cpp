#include "session.h"
#include "common.h"
#include "state.h"

namespace mls {

Session::Session(CipherList supported_ciphersuites,
                 bytes init_secret,
                 SignaturePrivateKey identity_priv,
                 Credential credential)
  : _supported_ciphersuites(std::move(supported_ciphersuites))
  , _identity_priv(std::move(identity_priv))
  , _credential(std::move(credential))
  , _current_epoch(0)
{
  make_init_key(init_secret);
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

bytes
Session::client_init_key() const
{
  return tls::marshal(_client_init_key);
}

std::pair<bytes, bytes>
Session::start(const bytes& group_id, const bytes& client_init_key_bytes)
{
  if (!_state.empty()) {
    throw InvalidParameterError("start called on an initialized session");
  }

  ClientInitKey client_init_key;
  tls::unmarshal(client_init_key_bytes, client_init_key);

  auto init = State::negotiate(
    group_id, _client_init_key, _identity_priv, client_init_key);

  add_state(0, std::get<2>(init));

  auto welcome = tls::marshal(std::get<0>(init));
  auto add = tls::marshal(std::get<1>(init));
  return std::make_pair(welcome, add);
}

std::pair<bytes, bytes>
Session::add(const bytes& client_init_key_bytes)
{
  ClientInitKey client_init_key;
  tls::unmarshal(client_init_key_bytes, client_init_key);
  auto welcome_add_state = current_state().add(client_init_key);
  auto welcome = tls::marshal(std::get<0>(welcome_add_state));
  auto add = tls::marshal(std::get<1>(welcome_add_state));
  auto state = std::get<2>(welcome_add_state);

  _outbound_cache = std::make_tuple(add, state);

  return std::pair<bytes, bytes>(welcome, add);
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
Session::join(const bytes& welcome_data, const bytes& add_data)
{
  Welcome welcome;
  tls::unmarshal(welcome_data, welcome);

  MLSPlaintext add{ welcome.cipher_suite };
  tls::unmarshal(add_data, add);

  State next(_identity_priv, _client_init_key, welcome, add);
  add_state(add.epoch, next);
}

void
Session::handle(const bytes& handshake_data)
{
  MLSPlaintext handshake{ current_state().cipher_suite() };
  tls::unmarshal(handshake_data, handshake);

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
  MLSCiphertext ciphertext_obj;
  tls::unmarshal(ciphertext, ciphertext_obj);

  if (_state.count(ciphertext_obj.epoch) == 0) {
    throw MissingStateError("No state available to decrypt ciphertext");
  }

  auto& state = _state.at(ciphertext_obj.epoch);
  return state.unprotect(ciphertext_obj);
}

void
Session::make_init_key(const bytes& init_secret)
{
  _client_init_key = ClientInitKey{};

  // XXX(rlb@ipv.sx) - It's probably not OK to derive all the keys
  // from the same secret.  Maybe we should include the ciphersuite
  // in the key derivation...
  //
  // Note, though, that since ClientInitKey objects track private
  // keys, it would be safe to just generate keys here, if we were
  // OK having internal keygen.
  for (auto suite : _supported_ciphersuites) {
    auto init_priv = DHPrivateKey::node_derive(suite, init_secret);
    _client_init_key.add_init_key(init_priv);
  }

  _client_init_key.sign(_identity_priv, _credential);
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

} // namespace mls
