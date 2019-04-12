#include "session.h"
#include "common.h"
#include "state.h"

namespace mls {

Session::Session(CipherList supported_ciphersuites,
                 bytes init_secret,
                 SignaturePrivateKey identity_priv,
                 Credential credential)
  : _supported_ciphersuites(std::move(supported_ciphersuites))
  , _init_secret(std::move(init_secret))
  , _identity_priv(std::move(identity_priv))
  , _credential(std::move(credential))
  , _current_epoch(0)
{
  make_init_key();
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

bytes
Session::user_init_key() const
{
  return _user_init_key;
}

std::pair<bytes, bytes>
Session::start(const bytes& group_id, const bytes& user_init_key_bytes)
{
  if (!_state.empty()) {
    throw InvalidParameterError("start called on an initialized session");
  }

  UserInitKey user_init_key;
  tls::unmarshal(user_init_key_bytes, user_init_key);

  auto init = State::negotiate(group_id,
                               _supported_ciphersuites,
                               _init_secret,
                               _identity_priv,
                               _credential,
                               user_init_key);

  auto root = init.first;
  add_state(0, root);

  auto welcome_add = init.second;
  auto welcome = tls::marshal(welcome_add.first);
  auto add = tls::marshal(welcome_add.second);
  return std::pair<bytes, bytes>(welcome, add);
}

std::pair<bytes, bytes>
Session::add(const bytes& user_init_key_bytes) const
{
  UserInitKey user_init_key;
  tls::unmarshal(user_init_key_bytes, user_init_key);
  auto welcome_add = current_state().add(user_init_key);
  auto welcome = tls::marshal(welcome_add.first);
  auto add = tls::marshal(welcome_add.second);
  return std::pair<bytes, bytes>(welcome, add);
}

bytes
Session::update(const bytes& leaf_secret)
{
  auto update = current_state().update(leaf_secret);
  return tls::marshal(update);
}

bytes
Session::remove(const bytes& evict_secret, uint32_t index) const
{
  auto update = current_state().remove(evict_secret, index);
  return tls::marshal(update);
}

void
Session::join(const bytes& welcome_data, const bytes& add_data)
{
  Welcome welcome;
  tls::unmarshal(welcome_data, welcome);

  Handshake add{ welcome.cipher_suite };
  tls::unmarshal(add_data, add);

  State next(_identity_priv, _credential, _init_secret, welcome, add);
  add_state(add.prior_epoch, next);
}

void
Session::handle(const bytes& handshake_data)
{
  Handshake handshake{ current_state().cipher_suite() };
  tls::unmarshal(handshake_data, handshake);

  auto next = current_state().handle(handshake);
  add_state(handshake.prior_epoch, next);
}

void
Session::make_init_key()
{
  auto user_init_key = UserInitKey{};

  // XXX(rlb@ipv.sx) - It's probably not OK to derive all the keys
  // from the same secret.  Maybe we should include the ciphersuite
  // in the key derivation...
  for (auto suite : _supported_ciphersuites) {
    auto init_priv = DHPrivateKey::node_derive(suite, _init_secret);
    user_init_key.add_init_key(init_priv.public_key());
  }

  user_init_key.sign(_identity_priv, _credential);
  _user_init_key = tls::marshal(user_init_key);
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

/////

namespace test {

uint32_t
TestSession::index() const
{
  return current_state().index();
}

epoch_t
TestSession::current_epoch() const
{
  return _current_epoch;
}

CipherSuite
TestSession::cipher_suite() const
{
  return current_state().cipher_suite();
}

bytes
TestSession::current_epoch_secret() const
{
  return current_state().epoch_secret();
}

bytes
TestSession::current_application_secret() const
{
  return current_state().application_secret();
}

bytes
TestSession::current_confirmation_key() const
{
  return current_state().confirmation_key();
}

bytes
TestSession::current_init_secret() const
{
  return current_state().init_secret();
}

} // namespace test

} // namespace mls
