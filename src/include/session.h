#pragma once

#include "common.h"
#include "state.h"
#include "tls_syntax.h"
#include <map>

namespace mls {

class Session
{
public:
  Session(CipherList supported_ciphersuites,
          bytes init_secret,
          SignaturePrivateKey identity_priv,
          Credential credential);

  // Two sessions are considered equal if:
  // (1) they agree on the states they have in common
  // (2) they agree on the current epoch
  friend bool operator==(const Session& lhs, const Session& rhs);

  bytes user_init_key() const;

  std::pair<bytes, bytes> start(const bytes& group_id,
                                const bytes& user_init_key);

  std::pair<bytes, bytes> add(const bytes& user_init_key) const;
  bytes update(const bytes& leaf_secret);
  bytes remove(const bytes& evict_secret, uint32_t index) const;

  void join(const bytes& welcome, const bytes& add);
  void handle(const bytes& handshake_data);

protected:
  CipherList _supported_ciphersuites;
  bytes _init_secret;
  tls::opaque<2> _user_init_key;
  SignaturePrivateKey _identity_priv;
  Credential _credential;
  std::map<epoch_t, State> _state;
  epoch_t _current_epoch;

  void make_init_key();
  void add_state(epoch_t prior_epoch, const State& state);
  State& current_state();
  const State& current_state() const;
};

namespace test {

// Enable tests to ispect the internals of the session
class TestSession : public Session
{
public:
  using Session::Session;
  uint32_t index() const;
  epoch_t current_epoch() const;
  CipherSuite cipher_suite() const;
  bytes current_epoch_secret() const;
  bytes current_application_secret() const;
  bytes current_confirmation_key() const;
  bytes current_init_secret() const;
};

}

} // namespace mls
