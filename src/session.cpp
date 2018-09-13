#include "session.h"
#include "tls_syntax.h"

namespace mls {

Session::Session(const bytes& group_id,
                 const SignaturePrivateKey& identity_priv)
  : _init_secret(random_bytes(32))
  , _next_leaf_secret(random_bytes(32))
  , _identity_priv(identity_priv)
{
  State root(group_id, identity_priv);
  add_state(root);
  make_init_key();
}

Session::Session(const SignaturePrivateKey& identity_priv)
  : _init_secret(random_bytes(32))
  , _next_leaf_secret(random_bytes(32))
  , _identity_priv(identity_priv)
{
  make_init_key();
}

Session::Session()
  : _init_secret(random_bytes(32))
  , _next_leaf_secret(random_bytes(32))
  , _identity_priv(SignaturePrivateKey::generate())
{
  make_init_key();
}

bool
operator==(const Session& lhs, const Session& rhs)
{
  if (lhs._current_epoch != rhs._current_epoch) {
    std::cout << "epoch mismatch" << lhs._current_epoch << " "
              << rhs._current_epoch << std::endl;
    return false;
  }

  for (const auto& pair : lhs._state) {
    if (rhs._state.count(pair.first) == 0) {
      continue;
    }

    if (rhs._state.at(pair.first) != pair.second) {
      std::cout << "state mismatch for epoch " << pair.first << std::endl;
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

bytes
Session::group_init_key() const
{
  auto group_init_key = current_state().group_init_key();
  return tls::marshal(group_init_key);
}

bytes
Session::join(const bytes& group_init_key_bytes)
{
  _group_init_key = group_init_key_bytes;
  GroupInitKey group_init_key;
  tls::unmarshal(group_init_key_bytes, group_init_key);
  auto user_add =
    State::join(_identity_priv, _next_leaf_secret, group_init_key);
  return tls::marshal(user_add);
}

bytes
Session::add(const bytes& user_init_key_bytes) const
{
  UserInitKey user_init_key;
  tls::unmarshal(user_init_key_bytes, user_init_key);
  auto group_add = current_state().add(user_init_key);
  return tls::marshal(group_add);
}

bytes
Session::update() const
{
  auto update = current_state().update(_next_leaf_secret);
  return tls::marshal(update);
}

bytes
Session::remove(uint32_t index) const
{
  auto update = current_state().remove(index);
  return tls::marshal(update);
}

void
Session::handle(const bytes& handshake)
{
  auto type = HandshakeType(handshake[0]);
  switch (type) {
    case HandshakeType::user_add: {
      Handshake<UserAdd> user_add;
      tls::unmarshal(handshake, user_add);

      if (_state.size() == 0) {
        // NB: Assumes that join() has been called previously
        GroupInitKey group_init_key;
        tls::unmarshal(_group_init_key, group_init_key);
        add_state(
          State(_identity_priv, _next_leaf_secret, user_add, group_init_key));
      } else {
        add_state(current_state().handle(user_add));
      }
    } break;

    case HandshakeType::group_add: {
      Handshake<GroupAdd> group_add;
      tls::unmarshal(handshake, group_add);

      if (_state.size() == 0) {
        add_state(State(_identity_priv, _init_secret, group_add));
      } else {
        add_state(current_state().handle(group_add));
      }
    } break;

    case HandshakeType::update: {
      Handshake<Update> update;
      tls::unmarshal(handshake, update);

      if (update.signer_index == current_state().index()) {
        add_state(current_state().handle(update, _next_leaf_secret));
        _next_leaf_secret = random_bytes(32);
      } else {
        add_state(current_state().handle(update));
      }

    } break;

    case HandshakeType::remove: {
      Handshake<Remove> remove;
      tls::unmarshal(handshake, remove);
      add_state(current_state().handle(remove));
    } break;

    default:
      throw InvalidMessageTypeError("Unknown HandshakeType");
  }
}

void
Session::make_init_key()
{
  auto init_priv = DHPrivateKey::derive(_init_secret);
  auto user_init_key = UserInitKey{
    {},                        // No cipher suites
    { init_priv.public_key() } // One init key
  };
  user_init_key.sign(_identity_priv);
  _user_init_key = tls::marshal(user_init_key);
}

void
Session::add_state(const State& state)
{
  // XXX(rlb@ipv.sx) Assumes no epoch collisions
  _state.emplace(state.epoch(), state);

  // XXX(rlb@ipv.sx) First successor updates the head pointer
  if (_current_epoch == state.prior_epoch() || _state.size() == 1) {
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
