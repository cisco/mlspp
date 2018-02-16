#include "messages.h"
#include "tls_syntax.h"
#include <catch.hpp>

using namespace mls;

template<typename T>
T
tls_round_trip(const T& before)
{
  tls::ostream w;
  w << before;

  T after;
  tls::istream r(w.bytes());
  r >> after;

  REQUIRE(before == after);
  return after;
}

TEST_CASE("Basic message serialization", "[messages]")
{
  auto identity_priv = SignaturePrivateKey::generate();
  auto merkle = MerkleNode::leaf(identity_priv.public_key().to_bytes());
  auto dh_pub = DHPrivateKey::generate().public_key();
  RatchetNode ratchet(dh_pub);

  UserInitKey user_init_key;
  user_init_key.generate(identity_priv);

  GroupInitKey group_init_key{ 0x01010101,
                               3,
                               { 0x03, 0x03, 0x03, 0x03 },
                               dh_pub,
                               { merkle, merkle },
                               { ratchet, ratchet } };

  SECTION("UserInitKey")
  {
    REQUIRE(user_init_key.verify());
    auto after = tls_round_trip(user_init_key);
    REQUIRE(after.verify());
  }

  SECTION("GroupInitKey")
  {
    tls_round_trip(group_init_key);

    auto root = (merkle + merkle).value();
    REQUIRE(group_init_key.identity_root() == root);
  }

  SECTION("HandshakeType") { tls_round_trip(HandshakeType::update); }

  SECTION("None") { tls_round_trip(None{}); }

  SECTION("UserAdd") { tls_round_trip(UserAdd{ { ratchet, ratchet } }); }

  SECTION("GroupAdd") { tls_round_trip(GroupAdd{ user_init_key }); }

  SECTION("Update") { tls_round_trip(Update{ { ratchet, ratchet } }); }

  SECTION("Remove") { tls_round_trip(Remove{ 0x42, { ratchet, ratchet } }); }
}

TEST_CASE("Handshake serialization", "[messages]")
{
  SignaturePrivateKey identity_priv = SignaturePrivateKey::generate();
  MerkleNode merkle = MerkleNode::leaf(identity_priv.public_key().to_bytes());
  auto dh_pub = DHPrivateKey::generate().public_key();
  RatchetNode ratchet(dh_pub);

  // Simulate a 3-node Merkle tree with the signer in position 1
  auto root = ((merkle + merkle) + merkle).value();

  UserInitKey user_init_key;
  user_init_key.generate(identity_priv);

  GroupInitKey group_init_key{ 0x01010101,
                               3,
                               { 0x03, 0x03, 0x03, 0x03 },
                               dh_pub,
                               { merkle + merkle, merkle },
                               { ratchet, ratchet } };

  Handshake<None> initial{
    None{}, 0x01010101, group_init_key, 1, { merkle, merkle }
    // identity_key omitted
    // signature omitted
  };

  initial.sign(identity_priv);
  REQUIRE(initial.verify(root));

  SECTION("None")
  {
    Handshake<None> before{
      {}, 0x01010101, group_init_key, 1, { merkle, merkle }
    };

    before.sign(identity_priv);
    auto after = tls_round_trip(before);
    REQUIRE(after.verify(root));
  }

  SECTION("UserAdd")
  {
    Handshake<UserAdd> before{ { { ratchet, ratchet } },
                               0x01010101,
                               group_init_key,
                               1,
                               { merkle, merkle } };

    before.sign(identity_priv);
    auto after = tls_round_trip(before);
    REQUIRE(after.verify(root));
  }

  SECTION("GroupAdd")
  {
    Handshake<GroupAdd> before{
      { user_init_key }, 0x01010101, group_init_key, 1, { merkle, merkle }
    };

    before.sign(identity_priv);
    auto after = tls_round_trip(before);
    REQUIRE(after.verify(root));
  }

  SECTION("Update")
  {
    Handshake<Update> before{ { { ratchet, ratchet } },
                              0x01010101,
                              group_init_key,
                              1,
                              { merkle, merkle } };

    before.sign(identity_priv);
    auto after = tls_round_trip(before);
    REQUIRE(after.verify(root));
  }

  SECTION("Remove")
  {
    Handshake<Remove> before{ { 0x42, { ratchet, ratchet } },
                              0x01010101,
                              group_init_key,
                              1,
                              { merkle, merkle } };

    before.sign(identity_priv);
    auto after = tls_round_trip(before);
    REQUIRE(after.verify(root));
  }
}
