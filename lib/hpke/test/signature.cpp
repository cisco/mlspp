#include <doctest/doctest.h>
#include <hpke/signature.h>

#include "common.h"

#include <vector>
TEST_CASE("Signature Known-Answer")
{
  ensure_fips_if_required();

  struct KnownAnswerTest
  {
    Signature::ID id;
    bool deterministic;
    bytes priv_serialized;
    bytes pub_serialized;
    bytes data;
    bytes signature;
  };

  const std::vector<KnownAnswerTest> cases{
    // TODO(RLB): Add ECDSA known-answer tests
    {
      // https://tools.ietf.org/html/rfc8032#section-7.1
      Signature::ID::Ed25519,
      true,
      from_hex("833fe62409237b9d62ec77587520911e"
               "9a759cec1d19755b7da901b96dca3d42"),
      from_hex("ec172b93ad5e563bf4932c70e1245034"
               "c35467ef2efd4d64ebf819683467e2bf"),
      from_hex("ddaf35a193617abacc417349ae204131"
               "12e6fa4e89a97ea20a9eeee64b55d39a"
               "2192992a274fc1a836ba3c23a3feebbd"
               "454d4423643ce80e2a9ac94fa54ca49f"),
      from_hex("dc2a4459e7369633a52b1bf277839a00"
               "201009a3efbf3ecb69bea2186c26b589"
               "09351fc9ac90b3ecfdfbc7c66431e030"
               "3dca179c138ac17ad9bef1177331a704"),
    },
    {
      // https://tools.ietf.org/html/rfc8032#section-7.2
      Signature::ID::Ed448,
      true,
      from_hex("d65df341ad13e008567688baedda8e9d"
               "cdc17dc024974ea5b4227b6530e339bf"
               "f21f99e68ca6968f3cca6dfe0fb9f4fa"
               "b4fa135d5542ea3f01"),
      from_hex("df9705f58edbab802c7f8363cfe5560a"
               "b1c6132c20a9f1dd163483a26f8ac53a"
               "39d6808bf4a1dfbd261b099bb03b3fb5"
               "0906cb28bd8a081f00"),
      from_hex("bd0f6a3747cd561bdddf4640a332461a"
               "4a30a12a434cd0bf40d766d9c6d458e5"
               "512204a30c17d1f50b5079631f64eb31"
               "12182da3005835461113718d1a5ef944"),
      from_hex("554bc2480860b49eab8532d2a533b7d5"
               "78ef473eeb58c98bb2d0e1ce488a98b1"
               "8dfde9b9b90775e67f47d4a1c3482058"
               "efc9f40d2ca033a0801b63d45b3b722e"
               "f552bad3b4ccb667da350192b61c508c"
               "f7b6b5adadc2c8d9a446ef003fb05cba"
               "5f30e88e36ec2703b349ca229c267083"
               "3900"),
    },
  };

  for (const auto& tc : cases) {
    if (fips() && fips_disable(tc.id)) {
      continue;
    }

    const auto& sig = select_signature(tc.id);

    auto priv = sig.deserialize_private(tc.priv_serialized);
    auto pub = priv->public_key();
    auto pub_serialized = sig.serialize(*pub);
    CHECK(pub_serialized == tc.pub_serialized);

    if (tc.deterministic) {
      auto signature = sig.sign(tc.data, *priv);
      CHECK(signature == tc.signature);
    }

    CHECK(sig.verify(tc.data, tc.signature, *pub));
  }
}

TEST_CASE("Signature Round-Trip")
{
  ensure_fips_if_required();

  const std::vector<Signature::ID> ids{
    Signature::ID::P256_SHA256, Signature::ID::P384_SHA384,
    Signature::ID::P521_SHA512, Signature::ID::Ed25519,
    Signature::ID::Ed448,       Signature::ID::RSA_SHA256,
    Signature::ID::RSA_SHA384,  Signature::ID::RSA_SHA512,
  };

  const auto data = from_hex("00010203");

  for (const auto& id : ids) {
    if (fips() && fips_disable(id)) {
      continue;
    }

    const auto& sig = select_signature(id);

    auto priv = std::unique_ptr<Signature::PrivateKey>(nullptr);
    if ((id == Signature::ID::RSA_SHA256) ||
        (id == Signature::ID::RSA_SHA384) ||
        (id == Signature::ID::RSA_SHA512)) {
      priv = Signature::generate_rsa(2048);
    } else {
      priv = sig.generate_key_pair();
    };

    auto pub = priv->public_key();
    auto signature = sig.sign(data, *priv);
    CHECK(sig.verify(data, signature, *pub));

    // serialize/deserialize private key
    auto priv_enc = sig.serialize_private(*priv);
    auto priv2 = sig.deserialize_private(priv_enc);
    auto pub2 = priv->public_key();

    auto signature2 = sig.sign(data, *priv2);
    CHECK(sig.verify(data, signature2, *pub2));

    // serialize/deserialize public key
    auto pub_enc = sig.serialize(*pub);
    auto pub3 = sig.deserialize(pub_enc);
    CHECK(sig.verify(data, signature2, *pub3));
  }
}
