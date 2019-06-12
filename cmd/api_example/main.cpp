#include "credential.h"
#include "crypto.h"
#include "messages.h"
#include "session.h"

#include <iostream>
#include <stdexcept>
#include <string>

using namespace mls;

const auto suites =
  std::vector<CipherSuite>{ CipherSuite::X25519_SHA256_AES128GCM };
const auto scheme = SignatureScheme::Ed25519;

Session
new_user(const std::string& name)
{
  auto init = random_bytes(32);
  auto priv = SignaturePrivateKey::generate(scheme);
  auto id = bytes(name.begin(), name.end());
  auto cred = Credential::basic(id, priv);
  return Session{ suites, init, cred };
}

// To be used with new API
class User
{
public:
  User(const std::string& name);
  ClientInitKey fresh_cik();
  ClientInitKey find_cik(const bytes& cik_id);

private:
  Credential _cred;
  std::map<bytes, ClientInitKey> _ciks;
};

void
verify_send(std::string label, Session& send, Session& recv)
{
  auto plaintext = bytes{ 0, 1, 2, 3 };
  auto encrypted = send.protect(plaintext);
  auto decrypted = recv.unprotect(encrypted);
  if (plaintext != decrypted) {
    throw std::runtime_error(label + ": send/receive failure");
  }
}

void
verify(std::string label, Session& alice, Session& bob)
{
  if (alice != bob) {
    throw std::runtime_error(label + ": not equal");
  }

  verify_send(label, alice, bob);
  verify_send(label, bob, alice);
}

int
main()
{
  /*

  Notes for future API:

  auto alice = User("alice");
  auto cikA = alice.fresh_cik();

  auto bob = User("bob");
  auto sessionB = Session::start(group_id, bob.credential);
  bytes welcome_data, add_data;
  std::tie(welcome_data, add_data) = sessionB.add(cikA);

  Welcome welcome;
  tls::unmarshal(welcome_data);
  auto cikA = alice.find_cik(welcome.client_init_key_id);

  auto sessionA = cikA.join(welcome, add_data);

  verify_send(sessionA, sessionB);
  verify_send(sessionB, sessionA);

  // Now update, then verify
  // Now add C, then verify
  // Now remove A, then verify

  */

  auto alice = new_user("alice");
  auto bob = new_user("bob");

  // Alice posts a ClientInitKey
  auto cikA = alice.client_init_key();

  // Bob starts a group and sends Alice a Welcome+Add
  auto group_id = bytes{ 0, 1, 2, 3 };
  auto welcome_add = bob.start(group_id, cikA);

  // Alice processes the Welcome+Add
  alice.join(welcome_add.first, welcome_add.second);

  // Alice and Bob should now be on the same page
  verify("create", alice, bob);

  // TODO: Credential keeps track of signature priv key
  // TODO: CIK-based session initialization
  // TODO: Make all these objects serializable so they can be saved

  std::cout << "ok" << std::endl;
  return 0;
}
