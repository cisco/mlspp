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

  friend bool operator==(const Session& lhs, const Session& rhs);

  bytes client_init_key() const;

  std::pair<bytes, bytes> start(const bytes& group_id,
                                const bytes& client_init_key);

  std::pair<bytes, bytes> add(const bytes& client_init_key);
  bytes update(const bytes& leaf_secret);
  bytes remove(const bytes& evict_secret, uint32_t index);

  void join(const bytes& welcome, const bytes& add);
  void handle(const bytes& handshake_data);

protected:
  CipherList _supported_ciphersuites;
  bytes _init_secret;
  tls::opaque<2> _client_init_key;
  SignaturePrivateKey _identity_priv;
  Credential _credential;
  std::map<epoch_t, State> _state;
  epoch_t _current_epoch;

  std::optional<std::tuple<bytes, State>> _outbound_cache;

  void make_init_key();
  void add_state(epoch_t prior_epoch, const State& state);
  State& current_state();
  const State& current_state() const;
};

} // namespace mls
