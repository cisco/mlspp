#include "common.h"
#include "nodes.h"
#include <catch.hpp>

using namespace mls;

TEST_CASE("Merkle tree nodes combine correctly", "[nodes]")
{
  // Manually computed using Python hashlib
  std::string left_hex =
    "971dc23b352fa9f2ec2ec4a83ff649306d8409c6239672c04fac23b4d77835b1";
  std::string right_hex =
    "8428c6e3134cefe7ab3c39e754905fb50161616bb631e9ecb17c11dfdceb1fe7";
  std::string parent_hex =
    "2626234131de95436ead7c51296cfee3e258aa23247fae85214e045f64c5f3d0";

  auto left_data = from_hex("00010203");
  auto right_data = from_hex("04050607");
  auto left_value = from_hex(left_hex);
  auto right_value = from_hex(right_hex);
  auto parent_value = from_hex(parent_hex);

  auto left = MerkleNode::leaf(left_data);
  auto right = MerkleNode::leaf(right_data);

  REQUIRE(left == left);
  REQUIRE(left != right);
  REQUIRE(left.value() == left_value);
  REQUIRE(right.value() == right_value);

  auto parent = left + right;
  REQUIRE(parent.value() == parent_value);
}

TEST_CASE("Merkle tree nodes serialize and deserialize", "[nodes]")
{
  auto before = MerkleNode::leaf(from_hex("00010203"));

  tls::ostream w;
  w << before;

  MerkleNode after;
  tls::istream r(w.bytes());
  r >> after;

  REQUIRE(before == after);
}

TEST_CASE("Ratchet tree nodes combine correctly", "[nodes]")
{
  auto left_data = from_hex("00010203");
  auto right_data = from_hex("04050607");

  auto left_priv_key = DHPrivateKey::derive(left_data);
  auto right_priv_key = DHPrivateKey::derive(right_data);
  auto parent_data = left_priv_key.derive(right_priv_key.public_key());
  auto parent_priv = DHPrivateKey::derive(parent_data);

  RatchetNode left_secret(left_data);
  RatchetNode left_priv(left_priv_key);
  RatchetNode left_pub(left_priv_key.public_key());

  RatchetNode right_secret(right_data);
  RatchetNode right_priv(right_priv_key);
  RatchetNode right_pub(right_priv_key.public_key());

  REQUIRE(left_secret == left_secret);
  REQUIRE(left_secret != right_secret);
  REQUIRE(left_secret != left_priv);
  REQUIRE(left_secret != left_pub);
  REQUIRE(left_secret.public_equal(left_priv));
  REQUIRE(left_secret.public_equal(left_pub));

  auto parent_priv_priv = left_priv + right_priv;
  auto parent_priv_pub = left_priv + right_pub;
  auto parent_pub_priv = left_pub + right_priv;

  REQUIRE(parent_priv_priv == parent_priv_pub);
  REQUIRE(parent_priv_priv == parent_pub_priv);
  REQUIRE(parent_priv_priv.secret() == parent_data);
  REQUIRE(parent_priv_priv.private_key() == parent_priv);
  REQUIRE(parent_priv_priv.public_key() == parent_priv.public_key());

  REQUIRE_THROWS_AS(left_pub + right_pub, IncompatibleNodesError);
}

TEST_CASE("Ratchet tree nodes serialize and deserialize", "[nodes]")
{
  auto before = DHPrivateKey::generate().public_key();

  tls::ostream w;
  w << before;

  RatchetNode after;
  tls::istream r(w.bytes());
  r >> after;

  REQUIRE(before == after);
}
