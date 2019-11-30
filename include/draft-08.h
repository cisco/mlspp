#pragma once

#include "common.h"
#include "credential.h"
#include "crypto.h"
#include "tls_syntax.h"
#include "ratchet_tree.h"

namespace draft08 {

using mls::CipherSuite;
using mls::HPKECiphertext;
using HPKEPublicKey = mls::DHPublicKey;
using mls::Credential;
using mls::RatchetTree;

///
/// Welcome
///

enum class ProtocolVersion : uint8_t
{
  mls10 = 0xFF,
};

struct KeyPackage {
  tls::opaque<1> epoch_secret;
  tls::opaque<1> path_secret;

  TLS_SERIALIZABLE(epoch_secret, path_secret);
};

struct GroupInfo {
  tls::opaque<1> group_id;
  uint32_t epoch;
  RatchetTree tree;
  tls::opaque<1> confirmed_transcript_hash;
  tls::opaque<1> interim_transcript_hash;

  tls::opaque<1> confirmation;
  uint32_t signer_index;
  tls::opaque<1> signature;

  TLS_SERIALIZABLE(group_id, epoch, tree, confirmed_transcript_hash, interim_transcript_hash, confirmation, signer_index, signature);
};

struct EncryptedKeyPackage {
  EncryptedKeyPackage(CipherSuite suite)
    : encrypted_key_package(suite)
  {}

  tls::opaque<1> client_init_key_hash;
  HPKECiphertext encrypted_key_package;

  TLS_SERIALIZABLE(client_init_key_hash, encrypted_key_package);
};

struct Welcome {
  ProtocolVersion version;
  CipherSuite cipher_suite;
  tls::variant_vector<EncryptedKeyPackage, CipherSuite, 4> key_packages;
  tls::opaque<4> encrypted_group_info;

  TLS_SERIALIZABLE(version, cipher_suite, key_packages, encrypted_group_info);
};

tls::ostream& operator<<(tls::ostream& str, const Welcome& obj);
tls::istream& operator>>(tls::istream& str, Welcome& obj);

///
/// ClientInitKey
///

struct State;

enum struct ExtensionType : uint16_t
{
  invalid = 0,
  supported_versions = 1,
  supported_ciphersuites = 2,
  expiration = 3,
};

struct Extension
{
  ExtensionType extension_type;
  tls::opaque<2> extension_data;

  TLS_SERIALIZABLE(extension_type, extension_data);
};

struct ClientInitKey {
  ProtocolVersion version;
  CipherSuite cipher_suite;
  HPKEPublicKey init_key;
  Credential credential;
  tls::vector<Extension, 2> extensions;
  tls::opaque<2> signature;

  TLS_SERIALIZABLE(version, cipher_suite, init_key, credential, extensions, signature);
};

///
/// State
///


// Ratchet tree: An empty ratchet tree
// Group ID: A value set by the creator
// Epoch: 0x00000000
// Tree hash: The root hash of the above ratchet tree
// Confirmed transcript hash: 0
// Interim transcript hash: 0
// Init secret: 0


struct State {
  ProtocolVersion version;
  CipherSuite cipher_suite;
  bytes group_id;
  uint32_t epoch;
  RatchetTree tree;
  bytes confirmed_transcript_hash;
  bytes interim_transcript_hash;

  bytes epoch_secret;
  bytes confirmation;

  State(CipherSuite cipher_suite_in, bytes group_id_in)
    : version(ProtocolVersion::mls10)
    , cipher_suite(cipher_suite_in)
    , group_id(group_id_in)
    , epoch(0)
  {
    // TODO set confirmed transcript hash = 0
    // TODO set interim transcript hash = 0
    // TODO set init secret = 0
  }

  std::tuple<Welcome, Commit>

};





} // namespace draft08
