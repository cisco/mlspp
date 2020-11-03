#include "mls/credential.h"
#include "mls/crypto.h"
#include "mls/messages.h"
#include "mls/session.h"

#include <iostream>
#include <stdexcept>
#include <string>

#include "version.h"

using namespace mls;

static mls::Client
create_client(CipherSuite suite, const std::string& name)
{
  auto id = bytes(name.begin(), name.end());
  auto sig_priv = SignaturePrivateKey::generate(suite);
  auto cred = Credential::basic(id, sig_priv.public_key);
  return Client(suite, sig_priv, cred);
}

static void
verify_send(const std::string& label, Session& send, Session& recv)
{
  auto plaintext = bytes{ 0, 1, 2, 3 };
  auto encrypted = send.protect(plaintext);
  auto decrypted = recv.unprotect(encrypted);
  if (plaintext != decrypted) {
    throw std::runtime_error(label + ": send/receive failure");
  }
}

static void
verify(const std::string& label, Session& alice, Session& bob)
{
  if (alice != bob) {
    throw std::runtime_error(label + ": not equal");
  }

  if (alice.roster() != bob.roster()) {
    throw std::runtime_error(label + ": roster not equal");
  }

  verify_send(label, alice, bob);
  verify_send(label, bob, alice);
}

int
main() // NOLINT(bugprone-exception-escape)
{

  std::cout << "Running library version:" << std::string(VERSION_SHORT) << std::endl;
  const auto suite =
    mls::CipherSuite{ mls::CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519 };

  ////////// DRAMATIS PERSONAE ///////////

  auto alice_client = create_client(suite, "alice");
  auto bob_client = create_client(suite, "bob");
  auto charlie_client = create_client(suite, "charlie");

  ////////// ACT I: CREATION ///////////

  auto group_id = bytes{ 0, 1, 2, 3 };
  auto alice_session = alice_client.begin_session(group_id);

  ////////// ACT II: ADDITION ///////////

  // Bob and Charlie post KeyPackages
  auto bob_join = bob_client.start_join();
  auto charlie_join = charlie_client.start_join();

  // Alice adds Bob and Charlie to the session
  auto add_bob = alice_session.add(bob_join.key_package());
  auto add_charlie = alice_session.add(charlie_join.key_package());
  auto [welcome, commit] = alice_session.commit({ add_bob, add_charlie });
  alice_session.handle(commit);

  // Bob and Charlie initialize their sessions
  auto bob_session = bob_join.complete(welcome);
  auto charlie_session = charlie_join.complete(welcome);

  verify("add A->B", alice_session, bob_session);
  verify("add A->C", alice_session, charlie_session);
  verify("add B->C", bob_session, charlie_session);

  ////////// ACT III: UPDATE ///////////

  // Bob updates his key
  auto update = bob_session.update();
  auto [_1, update_commit] = bob_session.commit({ update });
  silence_unused(_1);
  bob_session.handle(update_commit);

  // Everyone else processes the update and commit
  alice_session.handle(update);
  alice_session.handle(update_commit);
  charlie_session.handle(update);
  charlie_session.handle(update_commit);

  verify("update A->B", alice_session, bob_session);
  verify("update A->C", alice_session, charlie_session);
  verify("update B->C", bob_session, charlie_session);

  ////////// ACT IV: REMOVE ///////////

  // Charlie removes Bob
  auto remove = charlie_session.remove(1);
  auto [_2, remove_commit] = charlie_session.commit({ remove });
  silence_unused(_2);
  charlie_session.handle(remove_commit);

  // Alice and Charlie process the message (Bob is gone)
  alice_session.handle(remove);
  alice_session.handle(remove_commit);

  verify("remove A->C", alice_session, charlie_session);

  std::cout << "ok" << std::endl;
  return 0;
}
