#pragma once

#include <mls/common.h>
#include <mls/credential.h>
#include <mls/crypto.h>

namespace mls {

class PendingJoin;
class Session;

class Client
{
public:
  Client(CipherSuite suite_in,
         SignaturePrivateKey sig_priv_in,
         Credential cred_in);

  Session begin_session(const bytes& group_id) const;

  PendingJoin start_join() const;

private:
  const CipherSuite suite;
  const SignaturePrivateKey sig_priv;
  const Credential cred;
};

class PendingJoin
{
public:
  PendingJoin(const PendingJoin& other);
  ~PendingJoin();
  bytes key_package() const;
  Session complete(const bytes& welcome) const;

private:
  struct Inner;
  std::unique_ptr<Inner> inner;

  PendingJoin(Inner* inner);
  friend class Client;
};

class Session
{
public:
  Session(const Session& other);
  Session& operator=(const Session& other);
  ~Session();

  // Settings
  void encrypt_handshake(bool enabled);

  // Message producers
  bytes add(const bytes& key_package_data);
  bytes update();
  bytes remove(uint32_t index);
  std::tuple<bytes, bytes> commit(const bytes& proposal);
  std::tuple<bytes, bytes> commit(const std::vector<bytes>& proposals);
  std::tuple<bytes, bytes> commit();

  // Message consumers
  bool handle(const bytes& handshake_data);

  // Information about the current state
  epoch_t current_epoch() const;
  uint32_t index() const;
  bytes do_export(const std::string& label,
                  const bytes& context,
                  size_t size) const;
  std::vector<Credential> roster() const;

  // Application message protection
  bytes protect(const bytes& plaintext);
  bytes unprotect(const bytes& ciphertext);

protected:
  struct Inner;
  std::unique_ptr<Inner> inner;

  Session(Inner* inner);
  friend class Client;
  friend class PendingJoin;

  friend bool operator==(const Session& lhs, const Session& rhs);
  friend bool operator!=(const Session& lhs, const Session& rhs);
};

} // namespace mls
