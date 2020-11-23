#include <doctest/doctest.h>
#include <hpke/hpke.h>

#include "common.h"

#include <memory>
#include <vector>

TEST_CASE("AEAD Known-Answer")
{
  struct KnownAnswerTest
  {
    AEAD::ID id;
    bytes key;
    bytes nonce;
    bytes aad;
    bytes plaintext;
    bytes ciphertext;
  };

  const std::vector<KnownAnswerTest> cases{
    {
      // https://tools.ietf.org/html/draft-mcgrew-gcm-test-01#section-4
      AEAD::ID::AES_128_GCM,
      from_hex("4c80cdefbb5d10da906ac73c3613a634"),
      from_hex("2e443b684956ed7e3b244cfe"),
      from_hex("000043218765432100000000"),
      from_hex(
        "45000048699a000080114db7c0a80102c0a801010a9bf15638d3010000010000"
        "00000000045f736970045f756470037369700963796265726369747902646b00"
        "0021000101020201"),
      from_hex(
        "fecf537e729d5b07dc30df528dd22b768d1b98736696a6fd348509fa13ceac34"
        "cfa2436f14a3f3cf65925bf1f4a13c5d15b21e1884f5ff6247aeabb786b93bce"
        "61bc17d768fd9732459018148f6cbe722fd04796562dfdb4"),
    },
    {
      // https://tools.ietf.org/html/draft-mcgrew-gcm-test-01#section-4
      AEAD::ID::AES_256_GCM,
      from_hex(
        "abbccddef00112233445566778899aababbccddef00112233445566778899aab"),
      from_hex("112233440102030405060708"),
      from_hex("4a2cbfe300000002"),
      from_hex(
        "4500003069a6400080062690c0a801029389155e0a9e008b2dc57ee000000000"
        "7002400020bf0000020405b40101040201020201"),
      from_hex(
        "ff425c9b724599df7a3bcd510194e00d6a78107f1b0b1cbf06efae9d65a5d763"
        "748a637985771d347f0545659f14e99def842d8eb335f4eecfdbf831824b4c49"
        "15956c96"),
    },
    {
      // https://tools.ietf.org/html/rfc8439#appendix-A.5
      AEAD::ID::CHACHA20_POLY1305,
      from_hex(
        "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"),
      from_hex("000000000102030405060708"),
      from_hex("f33388860000000000004e91"),
      from_hex(
        "496e7465726e65742d4472616674732061726520647261667420646f63756d65"
        "6e74732076616c696420666f722061206d6178696d756d206f6620736978206d"
        "6f6e74687320616e64206d617920626520757064617465642c207265706c6163"
        "65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65"
        "6e747320617420616e792074696d652e20497420697320696e617070726f7072"
        "6961746520746f2075736520496e7465726e65742d4472616674732061732072"
        "65666572656e6365206d6174657269616c206f7220746f206369746520746865"
        "6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67"
        "726573732e2fe2809d"),
      from_hex(
        "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2"
        "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf"
        "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855"
        "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4"
        "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e"
        "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a"
        "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10"
        "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29"
        "a6ad5cb4022b02709beead9d67890cbb22392336fea1851f38"),
    },
  };

  for (const auto& tc : cases) {
    const auto& aead = select_aead(tc.id);

    auto encrypted = aead.seal(tc.key, tc.nonce, tc.aad, tc.plaintext);
    CHECK(encrypted == tc.ciphertext);

    auto decrypted = aead.open(tc.key, tc.nonce, tc.aad, tc.ciphertext);
    CHECK(decrypted == tc.plaintext);
  }
}

TEST_CASE("AEAD Round-Trip")
{
  const std::vector<AEAD::ID> ids{ AEAD::ID::AES_128_GCM,
                                   AEAD::ID::AES_256_GCM,
                                   AEAD::ID::CHACHA20_POLY1305 };

  const auto plaintext = from_hex("00010203");
  const auto aad = from_hex("04050607");

  for (const auto& id : ids) {
    const auto& aead = select_aead(id);
    auto key = bytes(aead.key_size, 0xA0);
    auto nonce = bytes(aead.nonce_size, 0xA1);

    auto encrypted = aead.seal(key, nonce, aad, plaintext);
    auto decrypted = aead.open(key, nonce, aad, encrypted);
    CHECK(decrypted == plaintext);
  }
}
