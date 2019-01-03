#include "messages.h"
#include "ratchet_tree.h"
#include "tls_syntax.h"
#include <catch.hpp>

#include <iostream>

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

    tree.add_leaf(secretB);
    tree.set_path(1, secretB);

    REQUIRE(tree.size() == 2);
    REQUIRE(tree.root_secret() == secretAB);

    tree.add_leaf(secretC);
    tree.set_path(2, secretC);

    REQUIRE(tree.size() == 3);
    REQUIRE(tree.root_secret() == secretABC);

    tree.add_leaf(secretD);
    tree.set_path(3, secretD);

    REQUIRE(tree.size() == 4);
    REQUIRE(tree.root_secret() == secretABCD);

    RatchetTree direct{ CIPHERSUITE, { secretA, secretB, secretC, secretD } };
    REQUIRE(tree == direct);
  }

  SECTION("Via serialization")
  {
    RatchetTree before{ CIPHERSUITE, { secretA, secretB, secretC, secretD } };
    RatchetTree after{ CIPHERSUITE };

    tls::unmarshal(tls::marshal(before), after);
    REQUIRE(before == after);
  }

  SECTION("Via serialization, with blanks")
  {
    RatchetTree before{ CIPHERSUITE, { secretA, secretB, secretC, secretD } };
    RatchetTree after{ CIPHERSUITE };

    before.blank_path(1);
    tls::unmarshal(tls::marshal(before), after);
    REQUIRE(before == after);
  }
}

TEST_CASE("Trees can encrypt and decrypt", "[ratchet-tree]")
{
  size_t size = 5;

  // trees[i] represents a tree with a private key for only leaf i
  std::vector<RatchetTree> trees(size, { CIPHERSUITE });
  for (int i = 0; i < size; ++i) {
    auto secret = random_bytes(32);
    auto priv = DHPrivateKey::derive(CIPHERSUITE, secret);
    auto pub = priv.public_key();

    for (int j = 0; j < size; ++j) {
      if (i == j) {
        trees[j].add_leaf(secret);
      } else {
        trees[j].add_leaf(pub);
      }
    }
  }

  for (int i = 0; i < size; ++i) {
    REQUIRE(trees[i].size() == size);
    REQUIRE(trees[i].check_invariant(i));
  }

  // Verify that each member can encrypt and be decrypted by the
  // other members
  for (int i = 0; i < size; ++i) {
    auto secret = random_bytes(32);
    auto ct = trees[i].encrypt(i, secret);

    for (int j = 0; j < size; ++j) {
      if (i == j) {
        trees[j].set_path(i, secret);
      } else {
        auto info = trees[j].decrypt(i, ct);
        trees[j].merge_path(i, info);
      }
    }

    for (int j = 0; j < size; ++j) {
      REQUIRE(trees[j].check_invariant(j));
      REQUIRE(trees[i] == trees[j]);
    }
  }
}
