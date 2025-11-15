#include <catch2/catch_all.hpp>
#include <hpke/hpke.h>

#include "common.h"

static const auto ids = std::vector<KEM::ID>
{
  KEM::ID::DHKEM_P256_SHA256, KEM::ID::DHKEM_P384_SHA384,
    KEM::ID::DHKEM_P384_SHA384, KEM::ID::DHKEM_P521_SHA512,
#if !defined(WITH_BORINGSSL)
    KEM::ID::DHKEM_X448_SHA512, KEM::ID::MLKEM512, KEM::ID::MLKEM768,
    KEM::ID::MLKEM1024, KEM::ID::MLKEM768_P256, KEM::ID::MLKEM1024_P384,
    KEM::ID::MLKEM768_X25519,
#endif
};

static const auto plaintext = from_hex("00010203");
static const auto seedS = from_hex("A0A0A0A0");
static const auto seedR = from_hex("B0B0B0B0");

TEST_CASE("KEM round-trip")
{
  ensure_fips_if_required();

  for (const auto& id : ids) {
    const auto& kem = select_kem(id);

    auto skS = kem.derive_key_pair(seedS);
    auto skR = kem.derive_key_pair(seedR);

    auto pkS = skS->public_key();
    auto pkR = skR->public_key();

    auto pkSm = kem.serialize(*pkS);
    REQUIRE(pkSm.size() == kem.pk_size);

    auto [secretS_, enc_] = kem.encap(*pkR);
    auto secretS = secretS_;
    auto enc = enc_;

    REQUIRE(enc.size() == kem.enc_size);
    REQUIRE(secretS.size() == kem.secret_size);

    auto secretR = kem.decap(enc, *skR);
    REQUIRE(secretR == secretS);
  }
}

TEST_CASE("AuthKEM round-trip")
{
  ensure_fips_if_required();

  static const auto no_auth = std::vector<KEM::ID>
  {
#if !defined(WITH_BORINGSSL)
    KEM::ID::MLKEM512, KEM::ID::MLKEM768, KEM::ID::MLKEM1024,
    KEM::ID::MLKEM768_P256, KEM::ID::MLKEM1024_P384, KEM::ID::MLKEM768_X25519
#endif
  };

  for (const auto& id : ids) {
    if (std::find(no_auth.begin(), no_auth.end(), id) != no_auth.end()) {
      continue;
    }

    const auto& kem = select_kem(id);

    auto skS = kem.derive_key_pair(seedS);
    auto skR = kem.derive_key_pair(seedR);

    auto pkS = skS->public_key();
    auto pkR = skR->public_key();

    auto pkSm = kem.serialize(*pkS);
    REQUIRE(pkSm.size() == kem.pk_size);

    auto [secretS_, enc_] = kem.auth_encap(*pkR, *skS);
    auto secretS = secretS_;
    auto enc = enc_;

    REQUIRE(enc.size() == kem.enc_size);
    REQUIRE(secretS.size() == kem.secret_size);

    auto secretR = kem.auth_decap(enc, *pkS, *skR);
    REQUIRE(secretR == secretS);
  }
}
