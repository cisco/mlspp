#pragma once

#include "mls/common.h"
#include "mls/state.h"
#include <map>
#include <tls/tls_syntax.h>

namespace mls {

class Session
{
public:
  struct InitInfo
  {
    HPKEPrivateKey init_priv;
    SignaturePrivateKey sig_priv;
    KeyPackage key_package;

    InitInfo(HPKEPrivateKey init_priv_in,
             SignaturePrivateKey sig_priv_in,
             KeyPackage key_package);
  };

  Session(const Session& other) = default;

  static std::tuple<Session, bytes> start(
    const bytes& group_id,
    const std::vector<InitInfo>& my_info,
    const std::vector<KeyPackage>& key_packages);
  static Session join(const std::vector<InitInfo>& my_info,
                      const bytes& welcome);

  void encrypt_handshake(bool enabled);

  bytes add(const KeyPackage& key_package);
  bytes update();
  bytes remove(uint32_t index);
  std::tuple<bytes, bytes> commit();

  bool handle(const bytes& handshake_data);

  bytes protect(const bytes& plaintext);
  bytes unprotect(const bytes& ciphertext);

protected:
  std::map<epoch_t, State> _state;
  epoch_t _current_epoch;
  bool _encrypt_handshake;

  std::optional<std::tuple<bytes, State>> _outbound_cache;

  Session();

  bytes fresh_secret() const;
  bytes export_message(const MLSPlaintext& plaintext);
  MLSPlaintext import_message(const bytes& encoded);

  void make_init_key(const HPKEPrivateKey& init_priv);
  void add_state(epoch_t prior_epoch, const State& state);
  State& current_state();
  const State& current_state() const;

  friend bool operator==(const Session& lhs, const Session& rhs);
  friend bool operator!=(const Session& lhs, const Session& rhs);
};

} // namespace mls
