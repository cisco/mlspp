#include <doctest/doctest.h>
#include <hpke/hpke.h>

#include "common.h"

// TODO(RLB): Add known-answer tests

TEST_CASE("KEM round-trip")
{
  const std::vector<KEM::ID> ids{ KEM::ID::DHKEM_P256_SHA256,
                                  KEM::ID::DHKEM_P384_SHA384,
                                  KEM::ID::DHKEM_P384_SHA384,
                                  KEM::ID::DHKEM_P521_SHA512,
                                  KEM::ID::DHKEM_X448_SHA512 };

  const auto plaintext = from_hex("00010203");
  const auto seedS = from_hex("A0A0A0A0");
  const auto seedR = from_hex("B0B0B0B0");

  for (const auto& id : ids) {
    const auto& kem = select_kem(id);

    auto skS = kem.derive_key_pair(seedS);
    auto skR = kem.derive_key_pair(seedR);

    auto pkS = skS->public_key();
    auto pkR = skR->public_key();

    auto pkSm = kem.serialize(*pkS);
    REQUIRE(pkSm.size() == kem.pk_size);

    SUBCASE("Encap/Decap")
    {
      auto [secretS, enc] = kem.encap(*pkR);
      REQUIRE(enc.size() == kem.enc_size);
      REQUIRE(secretS.size() == kem.secret_size);

      auto secretR = kem.decap(enc, *skR);
      REQUIRE(secretR == secretS);
    }

    SUBCASE("AuthEncap/AuthDecap")
    {
      auto [secretS, enc] = kem.auth_encap(*pkR, *skS);
      REQUIRE(enc.size() == kem.enc_size);
      REQUIRE(secretS.size() == kem.secret_size);

      auto secretR = kem.auth_decap(enc, *pkS, *skR);
      REQUIRE(secretR == secretS);
    }
  }
}
