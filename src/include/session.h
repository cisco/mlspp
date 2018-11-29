#pragma once

#include "common.h" // TODO(rlb@ipv.sx) Locally declare bytes
#include "state.h"  // TODO(rlb@ipv.sx) Forward declare State
#include "tls_syntax.h"
#include <map>

namespace mls {

class Session
{
public:
  // Create a session joined to an empty group
  Session(const bytes& group_id,
          CipherSuite suite,
          const SignaturePrivateKey& identity_priv);

  // Create an unjoined session
  Session(const SignaturePrivateKey& identity_priv);

  // Create an unjoined session (and auto-generate the identity key)
  Session();

  // Two sessions are considered equal if:
  // (1) they agree on the states they have in common
  // (2) they agree on the current epoch
  friend bool operator==(const Session& lhs, const Session& rhs);

  bytes user_init_key() const;

  std::pair<bytes, bytes> add(const bytes& user_init_key) const;
  bytes update();
  bytes remove(uint32_t index) const;

  void join(const bytes& welcome, const bytes& add);
  void handle(const bytes& handshake);

  epoch_t current_epoch() const { return _current_epoch; }

private:
  bytes _next_leaf_secret;
  bytes _init_secret;
  tls::opaque<2> _user_init_key;
  SignaturePrivateKey _identity_priv;
  std::map<epoch_t, State> _state;
  epoch_t _current_epoch;

  void make_init_key();
  void add_state(epoch_t prior_epoch, const State& state);
  State& current_state();
  const State& current_state() const;
  CipherSuite cipher_suite() const;
};

} // namespace mls
