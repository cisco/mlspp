#pragma once
#include "stdbool.h"
#include "stddef.h"
#include "stdint.h"
#ifdef __cplusplus
extern "C"
{
#endif
  typedef enum
  {
    unknown = 0x0000,
    X25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    P256_AES128GCM_SHA256_P256 = 0x0002,
    X25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    X448_AES256GCM_SHA512_Ed448 = 0x0004,
    P521_AES256GCM_SHA512_P521 = 0x0005,
    X448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,
  } mls_cipher_suite_id;

  typedef struct
  {
    uint8_t* data;
    size_t size;
  } mls_bytes;

  typedef struct
  {
    mls_bytes data1;
    mls_bytes data2;
  } mls_bytes_tuple;

  typedef struct Client Client;
  typedef struct Session Session;
  typedef struct PendingJoin PendingJoin;

  // API Wrapper
  extern Client* mls_create_client(mls_cipher_suite_id suite_id,
                                   const char name[]);
  extern Session* mls_begin_session(Client* client, mls_bytes group_id);
  extern PendingJoin* mls_start_join(Client* client);
  extern mls_bytes mls_pending_join_get_key_package(PendingJoin* join);
  extern Session* mls_pending_join_complete(PendingJoin* join,
                                            mls_bytes welcome);
  extern mls_bytes mls_session_add(Session* session, mls_bytes key_package);
  extern mls_bytes mls_session_update(Session* session);
  extern mls_bytes mls_session_remove(Session* session, uint32_t index);
  extern mls_bytes_tuple mls_session_commit(Session* session,
                                            mls_bytes proposals[],
                                            size_t proposals_size);
  extern bool mls_session_handle(Session* session, mls_bytes handshake_data);
  extern void verify(const char label[], Session* alice, Session* bob);

  // Destructor Wrapper
  extern void mls_delete_client(Client* client);
  extern void mls_delete_session(Session* session);
  extern void mls_delete_pending_join(PendingJoin* join);

  extern void mls_delete_bytes(mls_bytes bytes);
  extern void mls_delete_bytes_tuple(mls_bytes_tuple tuple);

#ifdef __cplusplus
}
#endif
