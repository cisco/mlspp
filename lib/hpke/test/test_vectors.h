#pragma once

#include <hpke/hpke.h>

#include "common.h"

#include <vector>

struct ExportTestVector
{
  bytes context;
  uint32_t length;
  bytes value;

  TLS_SERIALIZABLE(context, length, value)
};

struct EncryptionTestVector
{
  bytes plaintext;
  bytes aad;
  bytes nonce;
  bytes ciphertext;

  TLS_SERIALIZABLE(plaintext, aad, nonce, ciphertext)
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

  TLS_SERIALIZABLE(mode,
                   kem_id,
                   kdf_id,
                   aead_id,
                   info,
                   ikmR,
                   ikmS,
                   ikmE,
                   skRm,
                   skSm,
                   skEm,
                   psk,
                   psk_id,
                   pkRm,
                   pkSm,
                   pkEm,
                   enc,
                   shared_secret,
                   key_schedule_context,
                   secret,
                   key,
                   nonce,
                   exporter_secret,
                   encryptions,
                   exports)
};

struct HPKETestVectors
{
  std::vector<HPKETestVector> vectors;
  TLS_SERIALIZABLE(vectors);
};

extern const std::array<uint8_t, 2555172> test_vector_data;
