#include "ratchet_tree.h"
#include "tls_syntax.h"
#include <catch.hpp>

using namespace mls;

#define CIPHERSUITE CipherSuite::P256_SHA256_AES128GCM

TEST_CASE("Trees can be created and extended", "[ratchet-tree]")
{
  bytes secretA = from_hex("00010203");
  bytes secretB = from_hex("04050607");
  bytes secretC = from_hex("08090a0b");
  bytes secretD = from_hex("0c0d0e0f");
  bytes secretAB = from_hex(
    "c6d44cf418f610e3fe9e1d9294ff43def81c6cdcad6cbb1820cff48d3aa4355d");
  bytes secretCD = from_hex(
    "71b92110bf135c85581c8a128f6a19c0f6aca752b0c6c91e3571899cf09b145d");
  bytes secretABC = from_hex(
    "e0e6e3c1c64422cc76229d0c35ba817a281f8fc4014faa3e9152428a08a73ab3");
  bytes secretABCD = from_hex(
    "4e05f3b9649335c332f8a99cbaa56e637f3dc99a446f7f6af0f92ea7756717e0");

  SECTION("With one member")
  {
    RatchetTree tree{ CIPHERSUITE, secretA };
    REQUIRE(tree.size() == 1);
    REQUIRE(tree.root_secret() == secretA);
  }

  SECTION("With multiple members")
  {
    RatchetTree tree{ CIPHERSUITE, { secretA, secretB, secretC, secretD } };
    REQUIRE(tree.size() == 4);
    REQUIRE(tree.root_secret() == secretABCD);
  }

  SECTION("By extension")
  {
    RatchetTree tree{ CIPHERSUITE, secretA };

    auto ctB = tree.encrypt(1, secretB);
    auto rootAB = tree.decrypt(1, ctB);
    tree.merge(1, ctB);

    REQUIRE(tree.size() == 2);
    REQUIRE(tree.root_secret() == rootAB);
    REQUIRE(tree.root_secret() == secretAB);

    RatchetTree directAB{ CIPHERSUITE, { secretA, secretB } };
    REQUIRE(tree == directAB);

    auto ctC = tree.encrypt(2, secretC);
    auto rootABC = tree.decrypt(2, ctC);
    tree.merge(2, ctC);

    REQUIRE(tree.size() == 3);
    REQUIRE(tree.root_secret() == rootABC);
    REQUIRE(tree.root_secret() == secretABC);

    RatchetTree directABC{ CIPHERSUITE, { secretA, secretB, secretC } };
    REQUIRE(tree == directABC);

    auto ctD = tree.encrypt(3, secretD);
    auto rootABCD = tree.decrypt(3, ctD);
    tree.merge(3, ctD);

    REQUIRE(tree.size() == 4);
    REQUIRE(tree.root_secret() == rootABCD);
    REQUIRE(tree.root_secret() == secretABCD);

    RatchetTree direct{ CIPHERSUITE, { secretA, secretB, secretC, secretD } };
    REQUIRE(tree == direct);
  }

  SECTION("By adding leaves")
  {
    size_t size = 5;
    size_t depth = 4;

    bytes secretA = { 0, 1, 2, 3 };
    bytes secretB = { 1, 2, 3, 4 };
    RatchetTree tree{ CIPHERSUITE, secretA };
    tree.add_leaf(secretB);

    auto priv = DHPrivateKey::derive(CIPHERSUITE, { 2, 3, 4, 5 });
    auto pub = priv.public_key();
    for (uint8_t i = 2; i < size; ++i) {
      tree.add_leaf(pub);
    }

    REQUIRE(tree.size() == size);

    bytes original{ 0, 1, 2, 3 };
    auto encrypted = tree.encrypt(0, original);
    REQUIRE(encrypted.nodes.size() == depth);
    REQUIRE(encrypted.node_secrets.size() == size - 1);

    auto decrypted = tree.decrypt(0, encrypted);

    bytes digest = original;
    for (size_t i = 1; i < depth; ++i) {
      digest = Digest(CIPHERSUITE).write(digest).digest();
    }
    REQUIRE(decrypted == digest);
  }

  SECTION("Via serialization")
  {
    RatchetTree before{ CIPHERSUITE, { secretA, secretB, secretC, secretD } };
    RatchetTree after{ CIPHERSUITE };

    tls::unmarshal(tls::marshal(before), after);
    REQUIRE(before == after);
  }
}
