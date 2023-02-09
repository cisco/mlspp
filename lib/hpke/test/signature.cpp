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

TEST_CASE("Signature Verify Known-Answer")
{
  ensure_fips_if_required();

  struct KnownAnswerTest
  {
    Signature::ID id;
    bytes pub_serialized;
    bytes data;
    bytes signature;
  };

  const std::vector<KnownAnswerTest> cases{
    {
      Signature::ID::P256_SHA256,
      from_hex(
        "0490253da1fc5ffef719906c8f7d89371a7bb005fdd1325be3d2f1fd5e20615027e5da"
        "0143ce767f74f6a9b47078e37b6c021c830feae0166a03ab19051cfa43f5"),
      from_hex(
        "d0ea25121ae5f417f66b29ed46d6d9c8d166ee2c3d7209ccda6c01332e2aa7f9bac260"
        "dbcbaa54122aa05c7fd4ec82abde8e6322b1bbe34fb5a3cb438d7beccf37cd327c80bc"
        "7f4ad345ebfab406cbb2b532ac91e2875e337014805a839a53f3c9e2a2325298961336"
        "7ba1166578037e2c0ca8b9d9b9071dda6bc9b14689bdba"),
      from_hex("304402200d5b20abc4beee561c1d64d9145e4da8a186ffd28cdaf06ca65247d"
               "86f94b88c02203b6a5e140d2d13ebec80636bfb1e32d17fe3d7f2983a53104e"
               "101e766830453a"),
    },
    {
      Signature::ID::P384_SHA384,
      from_hex(
        "04d5a2abcb844865a479af773f9db66f5b8994710e2617e8b3c7ab4555f023f8e71a42"
        "291416cdf9ea288874c5cc9f38a49b6e7cc96a3a65f60a42a05e233af26c94e0cc23c8"
        "ee60177f1e1e3b52514a8de018addcc97245c2bef6bdd9ea7149da"),
      from_hex(
        "4be880bc0ccc92f79ed58b2c78268e28610719fb654b7d8b8aceae09e9e9ec3115de63"
        "3d5dbeb36762a67d48b0fd1c74cd499058557638372bb5d76f88a5ea00194f9c0b1578"
        "a9b5833d8d001ce847d4a55212601d514d6134f581f4c9a1f7bc5564ceaf28169c7fff"
        "70fbc67087da868826913dab1f1dcfdf045d027e7460b7"),
      from_hex(
        "3064023036da67b80ca54e25cffd8c7992d406118de661c9ff40ed0468938b04d71009"
        "7a3f5a947d2cb5420a5af6ca9b7a8684cb023042950fa4859def74cee5066f974b7a49"
        "cd43899468831970b736b7bbb95338d1dd0c9e9034c9801f414982580fe9e590"),
    },
    {
      Signature::ID::P521_SHA512,
      from_hex(
        "0400a659dcddfafe88ebbba8c04155870e0315794c7bd5a0c53ed9b57bcfaa36d79743"
        "5b40a74d62ba4104d62e166538e6f88d832aa047b6ed3cd119a477000f3362df01855f"
        "4e61ed4be7e81ed5f566ef6455a4fb588db6e6e44f57dc4271ac3d22cdba16d361db47"
        "8fa4fb233fd71179633e722615c33cfbd1d556cc29a839121c37b982"),
      from_hex(
        "6abe2712353e03ef03571a9679a3f1e889937d5ffc0df431fab44a408ce8cc37449f94"
        "28aae783a2ce200bb7ed546a1a92ea3555b45552844d15d6d86b662778e33124304691"
        "16615523990495dd3352b374792d591384123c3c7ca81ad42b9f6e856426a82dddd284"
        "d2f447df243067af6fe7f73cc4a368cb7cd53240af21d6"),
      from_hex(
        "3081880242015a033045a1bf86b3e1017826dd226604d78d129dcfca84f4020063beec"
        "03e0b4bedbedacbf1b0d1285ddbd0c7107078ac200be9876577025ffdd898e97f648f7"
        "80024201afcf701a73ab224ea5a0b6399fc231da0e7f1a8649df17ef2d5171fc4dc278"
        "6923727c2edc4f0ad9e98825750596be312d0109d47888ab6481c688a287b0aac6b0"),
    },
    {
      Signature::ID::Ed25519,
      from_hex(
        "923654bbdbacc72ab6c568208719c7cb866c3f89c366914ae90d604ef360c5c8"),
      from_hex(
        "dab12589702ff146b4e83b808da4007ff4ea4a358af2f7baa6861f08fb11ed71e338b2"
        "fa01c7a68f86daaed5c1f00683bd5a2e511f773ac3e664222692297d7b469fcae561e6"
        "1a8127bef87978449ec640883c0ba17d4f1741ed4ec94443b0fa0db1a139ad219ff7a4"
        "ac34ced9c7d74e4bf608a1d8f792c0bf28eedbf2536af7"),
      from_hex(
        "460396e559547d5faa532503b9a15bdd4d9b7415f3e71327adb1dd1cc21eb905dd9654"
        "136772745f5cc9d9ffdf6bed05b9b17491a2ae8309e847bc1c7f4d6e0c"),
    },
    {
      Signature::ID::Ed448,
      from_hex("7d60a1da10701ca4579de441643a545e334fddf18f6159ad2e8d2d914877a82"
               "ea95f0b1bdac911dfb2499d3ccf814ebe69b09f9914c6aca000"),
      from_hex(
        "074f95d4f746a270af113b5650da98dcb247ef9839e480e99961a2cc998058e2b98be3"
        "f949ceb7b000973127c0f79e54644f3b750763c2e904ac2179aa0a7e03da4e6d848f50"
        "8323ff81e4a6d20b4eb89fed06a9117383daa50e13d25e6e1c740691021379005d140a"
        "8e2157744cf7717f95a503d8e3740a081efa27146974c6"),
      from_hex("902aa0a168a9e7a547a1736fb52b491f857fe8984b9a5a5b2ae50b3c2c3b232"
               "894ae055013b256218cea79c4b4055719de3a6fbb2b0be0470062bc9e76f89e"
               "4ffc4c08cbd8ce50de80bae8029b78ced07cce09bc75c9b2eedcf402ed0e74c"
               "8078326f8ab69960d8062d2294ad1ff63901b00"),
    },
  };

  for (const auto& tc : cases) {
    const auto& sig = select_signature(tc.id);
    auto pub = sig.deserialize(tc.pub_serialized);
    auto valid = sig.verify(tc.data, tc.signature, *pub);
    CHECK(valid);
  }
}

// Samples generated via WebCrypto with the following:
//
// const data = new Uint8Array(128);
// crypto.getRandomValues(data);
//
// const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve:
// "P-256" }, true, ["sign", "verify"]); const
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
