#pragma once

#include <hpke/hpke.h>

#include "common.h"

#include <vector>

struct ExportTestVector
{
  bytes context;
  size_t length;
  bytes value;
};

struct EncryptionTestVector
{
  bytes plaintext;
  bytes aad;
  bytes nonce;
  bytes ciphertext;
};

struct HPKETestVector
{
  HPKE::Mode mode;
  KEM::ID kem_id;
  KDF::ID kdf_id;
  AEAD::ID aead_id;
  bytes info;
  bytes ikmR;
  bytes ikmS;
  bytes ikmE;
  bytes skRm;
  bytes skSm;
  bytes skEm;
  bytes psk;
  bytes psk_id;
  bytes pkRm;
  bytes pkSm;
  bytes pkEm;
  bytes enc;
  bytes shared_secret;
  bytes key_schedule_context;
  bytes secret;
  bytes key;
  bytes nonce;
  bytes exporter_secret;
  std::vector<EncryptionTestVector> encryptions;
  std::vector<ExportTestVector> exports;
};

extern std::vector<HPKETestVector> test_vectors;
