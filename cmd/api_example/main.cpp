#include "credential.h"
#include "crypto.h"
#include "messages.h"
#include "session.h"

#include <iostream>
#include <stdexcept>
#include <string>

using namespace mls;

const auto suite = CipherSuite::X25519_SHA256_AES128GCM;
const auto scheme = SignatureScheme::Ed25519;

class User
{
public:
  User(const std::string& name)
  {
    auto priv = SignaturePrivateKey::generate(scheme);
    auto id = bytes(name.begin(), name.end());
    _cred = Credential::basic(id, priv);
  }

  ClientInitKey temp_cik()
  {
    auto init_key = HPKEPrivateKey::generate(suite);
    return ClientInitKey{ init_key, _cred };
  }

  ClientInitKey fresh_cik()
  {
    auto cik = temp_cik();
    _ciks.push_back(cik);
    return cik;
  }

  const std::vector<ClientInitKey>& ciks() { return _ciks; }

private:
  Credential _cred;
  std::vector<ClientInitKey> _ciks;
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
  ////////// DRAMATIS PERSONAE ///////////

  auto alice = User{ "alice" };
  auto bob = User{ "bob" };
  auto charlie = User{ "charlie" };

  ////////// ACT I: CREATION ///////////

  // Bob posts a ClientInitKey
  auto cikB = bob.fresh_cik();

  // Alice starts a session with Bob
  auto cikA = alice.temp_cik();
  auto group_id = bytes{ 0, 1, 2, 3 };
  auto [sessionA, welcome] =
    Session::start(group_id, { cikA }, { cikB }, random_bytes(32));

  // Bob looks up his CIK based on the welcome, and initializes
  // his session
  auto sessionB = Session::join(bob.ciks(), welcome);

  // Alice and Bob should now be on the same page
  verify("create", sessionA, sessionB);

  ////////// ACT II: ADDITION ///////////

  // Charlie posts a ClientInitKey
  auto cikC1 = charlie.fresh_cik();

  // Alice adds Charlie to the session
  bytes add;
  std::tie(welcome, add) = sessionA.add(random_bytes(32), cikC1);

  // Charlie initializes his session
  auto sessionC = Session::join(charlie.ciks(), welcome);

  // Alice and Bob updates their sessions to reflect Charlie's addition
  sessionA.handle(add);
  sessionB.handle(add);

  verify("add A->B", sessionA, sessionB);
  verify("add A->C", sessionA, sessionC);
  verify("add B->C", sessionB, sessionC);

  ////////// ACT III: UPDATE ///////////

  // Bob updates his key
  auto update = sessionB.update(random_bytes(32));

  // Everyone processes the update
  sessionA.handle(update);
  sessionB.handle(update);
  sessionC.handle(update);

  verify("update A->B", sessionA, sessionB);
  verify("update A->C", sessionA, sessionC);
  verify("update B->C", sessionB, sessionC);

  ////////// ACT IV: REMOVE ///////////

  // Charlie removes Bob
  auto remove = sessionC.remove(random_bytes(32), 1);

  // Alice and Charlie process the message (Bob is gone)
  sessionA.handle(remove);
  sessionC.handle(remove);

  verify("remove A->C", sessionA, sessionC);

  std::cout << "ok" << std::endl;
  return 0;
}
