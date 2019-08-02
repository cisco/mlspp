#pragma once

#include "common.h"
#include "state.h"
#include "tls_syntax.h"
#include <map>

namespace mls {

class Session
{
public:
  Session(const Session& other) = default;

  static std::tuple<Session, Welcome, bytes>
    start(const bytes& group_id,
          const ClientInitKey& my_client_init_key,
          const ClientInitKey& client_init_key);
  static Session join(const ClientInitKey& client_init_key,
                      const Welcome& welcome,
                      const bytes& add);

  std::pair<Welcome, bytes> add(const ClientInitKey& client_init_key);
  bytes update(const bytes& leaf_secret);
  bytes remove(const bytes& evict_secret, uint32_t index);

  void handle(const bytes& handshake_data);

  bytes protect(const bytes& plaintext);
  bytes unprotect(const bytes& ciphertext);

protected:
  std::map<epoch_t, State> _state;
  epoch_t _current_epoch;

  std::optional<std::tuple<bytes, State>> _outbound_cache;

  Session() = default;

  void make_init_key(const bytes& init_secret);
  void add_state(epoch_t prior_epoch, const State& state);
  State& current_state();
  const State& current_state() const;

  friend bool operator==(const Session& lhs, const Session& rhs);
  friend bool operator!=(const Session& lhs, const Session& rhs);
};

} // namespace mls
