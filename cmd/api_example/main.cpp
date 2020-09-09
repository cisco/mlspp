#include "mls/credential.h"
#include "mls/crypto.h"
#include "mls/messages.h"
#include "mls/session.h"

#include <iostream>
#include <stdexcept>
#include <string>

using namespace mls;

const auto suite =
  CipherSuite{ CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519 };

class User
{
public:
  explicit User(const std::string& name)
    : _identity_priv(SignaturePrivateKey::generate(suite))
  {
    auto id = bytes(name.begin(), name.end());
    _cred = Credential::basic(id, _identity_priv.public_key);
  }

  Session::InitInfo temp_init_info()
  {
    auto init_secret = random_bytes(32);
    auto init_key = HPKEPrivateKey::derive(suite, init_secret);
    auto kp = KeyPackage{ suite, init_key.public_key, _cred, _identity_priv };
    return { init_secret, _identity_priv, kp };
  }

  KeyPackage fresh_key_package()
  {
    auto info = temp_init_info();
    _infos.push_back(info);
    return info.key_package;
  }

  const std::vector<Session::InitInfo>& infos() const { return _infos; }

private:
  SignaturePrivateKey _identity_priv;
  Credential _cred;
  std::vector<Session::InitInfo> _infos;
};

void
verify_send(const std::string& label, Session& send, Session& recv)
{
  auto plaintext = bytes{ 0, 1, 2, 3 };
  auto encrypted = send.protect(plaintext);
  auto decrypted = recv.unprotect(encrypted);
  if (plaintext != decrypted) {
    throw std::runtime_error(label + ": send/receive failure");
  }
}

void
verify(const std::string& label, Session& alice, Session& bob)
{
  if (alice != bob) {
    throw std::runtime_error(label + ": not equal");
  }

  verify_send(label, alice, bob);
  verify_send(label, bob, alice);
}

int
main() // NOLINT(bugprone-exception-escape)
{
  ////////// DRAMATIS PERSONAE ///////////

  auto alice = User{ "alice" };
  auto bob = User{ "bob" };
  auto charlie = User{ "charlie" };

  ////////// ACT I: CREATION ///////////

  // Bob posts a KeyPackage
  auto kpB = bob.fresh_key_package();

  // Alice starts a session with Bob
  auto infoA = alice.temp_init_info();
  auto group_id = bytes{ 0, 1, 2, 3 };
  auto [sessionA, welcome] =
    Session::start(group_id, { infoA }, { kpB }, random_bytes(32));

  // Bob looks up his CIK based on the welcome, and initializes
  // his session
  auto sessionB = Session::join(bob.infos(), welcome);

  // Alice and Bob should now be on the same page
  verify("create", sessionA, sessionB);

  ////////// ACT II: ADDITION ///////////

  // Charlie posts a KeyPackage
  auto kpC1 = charlie.fresh_key_package();

  // Alice adds Charlie to the session
  bytes add;
  std::tie(welcome, add) = sessionA.add(random_bytes(32), kpC1);

  // Charlie initializes his session
  auto sessionC = Session::join(charlie.infos(), welcome);

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
