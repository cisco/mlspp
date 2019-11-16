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
    auto cikID = random_bytes(16);
    auto init = random_bytes(32);
    return ClientInitKey{ cikID, suites, init, _cred };
  }

  ClientInitKey fresh_cik()
  {
    auto cik = temp_cik();
    _ciks.emplace(cik.client_init_key_id, cik);
    return cik;
  }

  ClientInitKey find_cik(const bytes& cik_id)
  {
    if (_ciks.count(cik_id) == 0) {
      throw std::runtime_error("Unkown CIK");
    }

    return _ciks.at(cik_id);
  }

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
  ////////// DRAMATIS PERSONAE ///////////

  auto alice = User{ "alice" };
  auto bob = User{ "bob" };
  auto charlie = User{ "charlie" };

  ////////// ACT I: CREATION ///////////

  // Bob posts a ClientInitKey
  auto cikB1 = bob.fresh_cik();

  // Alice starts a session with Bob
  auto cikA = alice.temp_cik();
  auto group_id = bytes{ 0, 1, 2, 3 };
  auto session_welcome_add = Session::start(group_id, cikA, cikB1);
  auto sessionA = std::get<0>(session_welcome_add);
  auto welcome = std::get<1>(session_welcome_add);
  auto add = std::get<2>(session_welcome_add);

  // Bob looks up his CIK based on the welcome, and initializes
  // his session
  auto cikB2 = bob.find_cik(welcome.client_init_key_id);
  auto sessionB = Session::join(cikB2, welcome, add);

  // Alice and Bob should now be on the same page
  verify("create", sessionA, sessionB);

  ////////// ACT II: ADDITION ///////////

  // Charlie posts a ClientInitKey
  auto cikC1 = charlie.fresh_cik();

  // Alice adds Charlie to the session
  std::tie(welcome, add) = sessionA.add(cikC1);

  // Charlie initializes his session
  auto cikC2 = charlie.find_cik(welcome.client_init_key_id);
  auto sessionC = Session::join(cikC2, welcome, add);

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
