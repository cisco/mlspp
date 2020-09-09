#include <doctest/doctest.h>
#include <hpke/hpke.h>

#include "common.h"
#include "test_vectors.h"

static void
test_context(ReceiverContext& ctxR, const HPKETestVector& tv)
{
  for (const auto& enc : tv.encryptions) {
    auto plaintext = ctxR.open(enc.aad, enc.ciphertext);
    REQUIRE(plaintext == enc.plaintext);
  }

  for (const auto& exp : tv.exports) {
    auto value = ctxR.do_export(exp.context, exp.length);
    REQUIRE(value == exp.value);
  }
}

static void
test_base_vector(const HPKETestVector& tv)
{
  const auto& kem = select_kem(tv.kem_id);
  auto hpke = HPKE(tv.kem_id, tv.kdf_id, tv.aead_id);

  auto skR = kem.derive_key_pair(tv.seedR);
  auto pkR = skR->public_key();
  auto pkRm = kem.serialize(*pkR);
  REQUIRE(pkRm == tv.pkRm);

  auto ctxR = hpke.setup_base_r(tv.enc, *skR, tv.info);
  test_context(ctxR, tv);
}

static void
test_psk_vector(const HPKETestVector& tv)
{
  const auto& kem = select_kem(tv.kem_id);
  auto hpke = HPKE(tv.kem_id, tv.kdf_id, tv.aead_id);

  auto skR = kem.derive_key_pair(tv.seedR);
  auto skRm = kem.serialize_private(*skR);

  auto pkR = skR->public_key();
  auto pkRm = kem.serialize(*pkR);
  REQUIRE(pkRm == tv.pkRm);

  auto ctxR = hpke.setup_psk_r(tv.enc, *skR, tv.info, tv.psk, tv.psk_id);
  test_context(ctxR, tv);
}

static void
test_auth_vector(const HPKETestVector& tv)
{
  const auto& kem = select_kem(tv.kem_id);
  auto hpke = HPKE(tv.kem_id, tv.kdf_id, tv.aead_id);

  auto skS = kem.derive_key_pair(tv.seedS);
  auto pkS = skS->public_key();
  auto pkSm = kem.serialize(*pkS);
  REQUIRE(pkSm == tv.pkSm);

  auto skR = kem.derive_key_pair(tv.seedR);
  auto pkR = skR->public_key();
  auto pkRm = kem.serialize(*pkR);
  REQUIRE(pkRm == tv.pkRm);

  auto ctxR = hpke.setup_auth_r(tv.enc, *skR, tv.info, *pkS);
  test_context(ctxR, tv);
}

static void
test_auth_psk_vector(const HPKETestVector& tv)
{
  const auto& kem = select_kem(tv.kem_id);
  auto hpke = HPKE(tv.kem_id, tv.kdf_id, tv.aead_id);

  auto skS = kem.derive_key_pair(tv.seedS);
  auto pkS = skS->public_key();
  auto pkSm = kem.serialize(*pkS);
  REQUIRE(pkSm == tv.pkSm);

  auto skR = kem.derive_key_pair(tv.seedR);
  auto pkR = skR->public_key();
  auto pkRm = kem.serialize(*pkR);
  REQUIRE(pkRm == tv.pkRm);

  auto ctxR =
    hpke.setup_auth_psk_r(tv.enc, *skR, tv.info, tv.psk, tv.psk_id, *pkS);
  test_context(ctxR, tv);
}

TEST_CASE("HPKE Test Vectors")
{
  for (const auto& tv : test_vectors) {
    switch (tv.mode) {
      case HPKE::Mode::base:
        test_base_vector(tv);
        break;

      case HPKE::Mode::psk:
        test_psk_vector(tv);
        break;

      case HPKE::Mode::auth:
        test_auth_vector(tv);
        break;

      case HPKE::Mode::auth_psk:
        test_auth_psk_vector(tv);
        break;
    }
  }
}

TEST_CASE("HPKE Round-Trip")
{
  const std::vector<KEM::ID> kems{ KEM::ID::DHKEM_P256_SHA256,
                                   KEM::ID::DHKEM_P384_SHA384,
                                   KEM::ID::DHKEM_P384_SHA384,
                                   KEM::ID::DHKEM_P521_SHA512,
                                   KEM::ID::DHKEM_X448_SHA512 };
  const std::vector<KDF::ID> kdfs{ KDF::ID::HKDF_SHA256,
                                   KDF::ID::HKDF_SHA384,
                                   KDF::ID::HKDF_SHA512 };
  const std::vector<AEAD::ID> aeads{ AEAD::ID::AES_128_GCM,
                                     AEAD::ID::AES_256_GCM,
                                     AEAD::ID::CHACHA20_POLY1305 };

  const auto info = from_hex("00010203");
  const auto plaintext = from_hex("04050607");
  const auto aad = from_hex("08090a0b");
  const auto seedS = from_hex("A0A0A0A0");
  const auto seedR = from_hex("B0B0B0B0");
  const auto iterations = int(256);

  for (const auto& kem_id : kems) {
    const auto& kem = select_kem(kem_id);
    auto skS = kem.derive_key_pair(seedS);
    auto skR = kem.derive_key_pair(seedR);

    auto pkS = skS->public_key();
    auto pkR = skR->public_key();

    for (const auto& kdf_id : kdfs) {
      for (const auto& aead_id : aeads) {
        auto hpke = HPKE(kem_id, kdf_id, aead_id);

        auto [enc, ctxS] = hpke.setup_base_s(*pkR, info);
        auto ctxR = hpke.setup_base_r(enc, *skR, info);
        REQUIRE(ctxS == ctxR);
        // TODO(RLB): Define operator==, CHECK(ctxS == ctxR)

        auto last_encrypted = bytes{};
        for (int i = 0; i < iterations; i += 1) {
          auto encrypted = ctxS.seal(aad, plaintext);
          REQUIRE(encrypted != last_encrypted);

          auto decrypted = ctxR.open(aad, encrypted);
          REQUIRE(decrypted == plaintext);

          last_encrypted = encrypted;
        }
      }
    }
  }
}
