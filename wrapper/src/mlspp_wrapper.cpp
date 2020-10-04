#include "mlspp_wrapper.h"
#include "bytes/bytes.h"
#include <cstring>
#include <iostream>
#include <mls/session.h>

mls::Client
create_client(mls::CipherSuite suite, const std::string& name);
bool
mls_copy_bytes(mls_bytes* dest, bytes* src);
bool
mls_tuple_conversion(mls_bytes_tuple* dest, std::tuple<bytes, bytes>* src);
void
verify_send(const std::string& label, mls::Session& send, mls::Session& recv);
void
verify(const std::string& label, mls::Session& alice, mls::Session& bob);

extern "C"
{
  extern Client* mls_create_client(mls_cipher_suite_id suite_id,
                                   const char name[])
  {
    auto suite = mls::CipherSuite{ (mls::CipherSuite::ID)suite_id };
    std::string bla = name;
    return (Client*)new mls::Client(create_client(suite, bla));
  }

  extern Session* mls_begin_session(Client* client, mls_bytes group_id)
  {
    bytes grp_id = bytes(group_id.data, group_id.data + group_id.size);
    auto mls_client = (mls::Client*)client;
    auto mls_session = new mls::Session(mls_client->begin_session(grp_id));
    return (Session*)mls_session;
  }

  extern PendingJoin* mls_start_join(Client* client)
  {
    auto mls_client = (mls::Client*)client;
    auto pending_join = mls_client->start_join();
    return (PendingJoin*)new mls::PendingJoin(pending_join);
  }

  extern mls_bytes mls_pending_join_get_key_package(PendingJoin* join)
  {
    auto pending_join = (mls::PendingJoin*)join;
    auto key_package = pending_join->key_package();
    mls_bytes kp_bytes = {};
    kp_bytes.data = (uint8_t*)malloc(key_package.size());
    kp_bytes.size = key_package.size();
    mls_copy_bytes(&kp_bytes, &key_package);
    return kp_bytes;
  }

  extern Session* mls_pending_join_complete(PendingJoin* join,
                                            mls_bytes welcome)
  {
    auto pending_join = (mls::PendingJoin*)join;
    auto session = new mls::Session(
      pending_join->complete(bytes(welcome.data, welcome.data + welcome.size)));
    return (Session*)session;
  }

  extern mls_bytes mls_session_add(Session* session, mls_bytes key_package)
  {
    auto add_session = (mls::Session*)session;
    auto add_kp = bytes(key_package.data, key_package.data + key_package.size);
    auto add_bytes = add_session->add(add_kp);
    mls_bytes add = {};
    add.data = (uint8_t*)malloc(add_bytes.size());
    add.size = add_bytes.size();
    mls_copy_bytes(&add, &add_bytes);
    return add;
  }

  extern mls_bytes mls_session_update(Session* session)
  {
    auto update_session = (mls::Session*)session;
    auto update_bytes = update_session->update();
    mls_bytes update = {};
    update.data = (uint8_t*)malloc(update_bytes.size());
    update.size = update_bytes.size();
    mls_copy_bytes(&update, &update_bytes);
    return update;
  }

  extern mls_bytes mls_session_remove(Session* session, uint32_t index)
  {
    auto remove_session = (mls::Session*)session;
    auto remove_bytes = remove_session->remove(index);
    mls_bytes remove = {};
    remove.data = (uint8_t*)malloc(remove_bytes.size());
    remove.size = remove_bytes.size();
    mls_copy_bytes(&remove, &remove_bytes);
    return remove;
  }

  extern mls_bytes_tuple mls_session_commit(Session* session,
                                            mls_bytes proposals[],
                                            size_t proposals_size)
  {
    auto commit_session = (mls::Session*)session;
    std::vector<bytes> commit_proposals(proposals_size);
    for (uint64_t i = 0; i < proposals_size; i++) {
      commit_proposals.at(i) =
        bytes(proposals[i].data, proposals[i].data + proposals[i].size);
    }
    auto commit_result = commit_session->commit(commit_proposals);
    mls_bytes_tuple welcome_commit = {};
    welcome_commit.data1.data =
      (uint8_t*)malloc(std::get<0>(commit_result).size());
    welcome_commit.data1.size = std::get<0>(commit_result).size();
    welcome_commit.data2.data =
      (uint8_t*)malloc(std::get<1>(commit_result).size());
    welcome_commit.data2.size = std::get<1>(commit_result).size();
    mls_tuple_conversion(&welcome_commit, &commit_result);
    return welcome_commit;
  }

  extern bool mls_session_handle(Session* session, mls_bytes handshake_data)
  {
    auto handle_session = (mls::Session*)session;
    auto handshake_bytes =
      bytes(handshake_data.data, handshake_data.data + handshake_data.size);
    return handle_session->handle(handshake_bytes);
  }

  extern void verify(const char label[], Session* alice, Session* bob)
  {
    std::string str_label = label;
    auto alice_session = (mls::Session*)alice;
    auto bob_session = (mls::Session*)bob;
    verify(str_label, *alice_session, *bob_session);
  }

  // Destructor Wrapper

  extern void mls_delete_client(Client* client) { delete (mls::Client*)client; }

  extern void mls_delete_session(Session* session)
  {
    delete (mls::Session*)session;
  }

  extern void mls_delete_pending_join(PendingJoin* join)
  {
    delete (mls::PendingJoin*)join;
  }

  extern void mls_delete_bytes(mls_bytes bytes) { free(bytes.data); }

  extern void mls_delete_bytes_tuple(mls_bytes_tuple tuple)
  {
    mls_delete_bytes(tuple.data1);
    mls_delete_bytes(tuple.data2);
  }
}

mls::Client
create_client(mls::CipherSuite suite, const std::string& name)
{
  auto id = bytes_ns::bytes(name.begin(), name.end());
  auto sig_priv = mls::SignaturePrivateKey::generate(suite);
  auto cred = mls::Credential::basic(id, sig_priv.public_key);
  return mls::Client(suite, sig_priv, cred);
}

void
verify_send(const std::string& label, mls::Session& send, mls::Session& recv)
{
  auto plaintext = bytes{ 0, 1, 2, 3 };
  auto encrypted = send.protect(plaintext);
  auto decrypted = recv.unprotect(encrypted);
  if (plaintext != decrypted) {
    throw std::runtime_error(label + ": send/receive failure");
  }
}

void
verify(const std::string& label, mls::Session& alice, mls::Session& bob)
{
  if (alice != bob) {
    throw std::runtime_error(label + ": not equal");
  }
  verify_send(label, alice, bob);
  verify_send(label, bob, alice);
}

bool
mls_copy_bytes(mls_bytes* dest, bytes* src)
{
  if (dest != nullptr && src != nullptr) {
    size_t size = src->size();
    for (unsigned long i = 0; i < size; i++) {
      memcpy(&dest->data[i], (uint8_t*)&src->at(i), sizeof(uint8_t));
    }
    return true;
  } else {
    return false;
  }
}

bool
mls_tuple_conversion(mls_bytes_tuple* dest, std::tuple<bytes, bytes>* src)
{
  if (dest != nullptr && src != nullptr) {
    mls_copy_bytes(&dest->data1, &std::get<0>(*src));
    mls_copy_bytes(&dest->data2, &std::get<1>(*src));
    return true;
  } else {
    return false;
  }
}
