#include "mlspp_wrapper.h"
#include "stdio.h"

int
main()
{
  ////////// DRAMATIS PERSONAE ///////////

  Client* alice =
    mls_create_client(X25519_CHACHA20POLY1305_SHA256_Ed25519, "alice");
  Client* bob =
    mls_create_client(X25519_CHACHA20POLY1305_SHA256_Ed25519, "bob");
  Client* charlie =
    mls_create_client(X25519_CHACHA20POLY1305_SHA256_Ed25519, "charlie");

  ////////// ACT I: CREATION ////////////

  mls_bytes group_id = { 0 };
  uint8_t data[] = { 0, 1, 2, 3 };
  group_id.data = data;
  group_id.size = sizeof(data) / sizeof(data[0]);
  Session* alice_session = mls_begin_session(alice, group_id);

  ////////// ACT II: ADDITION ///////////

  // Bob and Charlie post KeyPackages
  PendingJoin* bob_join = mls_start_join(bob);
  PendingJoin* charlie_join = mls_start_join(charlie);

  // Alice adds Bob and Charlie to the session
  mls_bytes add_bob =
    mls_session_add(alice_session, mls_pending_join_get_key_package(bob_join));
  mls_bytes add_charlie = mls_session_add(
    alice_session, mls_pending_join_get_key_package(charlie_join));
  mls_bytes add_proposals[] = { add_bob, add_charlie };
  mls_bytes_tuple welcome_commit =
    mls_session_commit(alice_session, add_proposals, 2);
  mls_session_handle(alice_session, welcome_commit.data2);

  // Bob and Charlie initialize their sessions
  Session* bob_session =
    mls_pending_join_complete(bob_join, welcome_commit.data1);
  Session* charlie_session =
    mls_pending_join_complete(charlie_join, welcome_commit.data1);

  verify("add A->B", alice_session, bob_session);
  verify("add A->C", alice_session, charlie_session);
  verify("add B->C", bob_session, charlie_session);

  ////////// ACT III: UPDATE ///////////

  // Bob updates his key
  mls_bytes update = mls_session_update(bob_session);
  mls_bytes update_proposals[] = { update };
  mls_bytes_tuple update_commit =
    mls_session_commit(bob_session, update_proposals, 1);
  mls_session_handle(bob_session, update_commit.data2);

  // Everyone else processes the update and commit
  mls_session_handle(alice_session, update);
  mls_session_handle(alice_session, update_commit.data2);
  mls_session_handle(charlie_session, update);
  mls_session_handle(charlie_session, update_commit.data2);

  verify("update A->B", alice_session, bob_session);
  verify("update A->C", alice_session, charlie_session);
  verify("update B->C", bob_session, charlie_session);

  ////////// ACT IV: REMOVE ///////////

  // Charlie removes Bob
  mls_bytes remove = mls_session_remove(charlie_session, 1);
  mls_bytes remove_proposals[] = { remove };
  mls_bytes_tuple remove_commit =
    mls_session_commit(charlie_session, remove_proposals, 1);
  mls_session_handle(charlie_session, remove_commit.data2);

  // Alice and Charlie process the message (Bob is gone)
  mls_session_handle(alice_session, remove);
  mls_session_handle(alice_session, remove_commit.data2);

  verify("remove A->C", alice_session, charlie_session);

  ////////// ACT V: Cleanup ///////////

  // Free clients
  mls_delete_client(alice);
  mls_delete_client(bob);
  mls_delete_client(charlie);

  // Free sessions
  mls_delete_session(alice_session);
  mls_delete_session(bob_session);
  mls_delete_session(charlie_session);

  // Free pendingjoins
  mls_delete_pending_join(bob_join);
  mls_delete_pending_join(charlie_join);

  // Free bytes
  mls_delete_bytes(add_bob);
  mls_delete_bytes(add_charlie);
  mls_delete_bytes(update);
  mls_delete_bytes(remove);

  // Free byte tuples
  mls_delete_bytes_tuple(welcome_commit);
  mls_delete_bytes_tuple(update_commit);
  mls_delete_bytes_tuple(remove_commit);

  printf("ok\n");
  return 0;
}
