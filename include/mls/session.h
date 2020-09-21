#pragma once

#include "mls/common.h"
#include "mls/state.h"
#include <map>
#include <tls/tls_syntax.h>

namespace mls {

class PendingJoin;
class Session;

class Client {
public:
  Client(CipherSuite suite_in, SignaturePrivateKey sig_priv_in, Credential cred_in);

  Session begin_session(const bytes& group_id) const;

  PendingJoin start_join() const;

private:
  const CipherSuite suite;
  const SignaturePrivateKey sig_priv;
  const Credential cred;
};

class PendingJoin {
public:
  bytes key_package() const;
  Session complete(const bytes& welcome) const;

private:
  const CipherSuite suite;
  const HPKEPrivateKey init_priv;
  const SignaturePrivateKey sig_priv;
  const KeyPackage key_package_inner;

  PendingJoin(CipherSuite suite_in, SignaturePrivateKey sig_priv_in, Credential cred_in);
  friend class Client;
};

class Session
{
public:
  Session(const Session& other) = default;

  // Settings
  void encrypt_handshake(bool enabled);

  // Message producers
  bytes add(const bytes& key_package_data);
  bytes update();
  bytes remove(uint32_t index);
  std::tuple<bytes, bytes> commit();

  // Message consumers
  bool handle(const bytes& handshake_data);

  // Application message protection
  bytes protect(const bytes& plaintext);
  bytes unprotect(const bytes& ciphertext);

protected:
  std::map<epoch_t, State> _state;
  epoch_t _current_epoch;
  bool _encrypt_handshake;

  std::optional<std::tuple<bytes, State>> _outbound_cache;

  // Session creators
  Session();
  static Session begin(const bytes& group_id,
                       const HPKEPrivateKey& init_priv,
                       const SignaturePrivateKey& sig_priv,
                       const KeyPackage& key_package);
  static Session join(const HPKEPrivateKey& init_priv,
                      const SignaturePrivateKey& sig_priv,
                      const KeyPackage& key_package,
                      const bytes& welcome_data);

  friend class Client;
  friend class PendingJoin;

  bytes fresh_secret() const;
  bytes export_message(const MLSPlaintext& plaintext);
  MLSPlaintext import_message(const bytes& encoded);

  void add_state(epoch_t prior_epoch, const State& state);
  State& current_state();
  const State& current_state() const;

  friend bool operator==(const Session& lhs, const Session& rhs);
  friend bool operator!=(const Session& lhs, const Session& rhs);
};

} // namespace mls
