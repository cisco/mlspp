#include "messages.h"
#include "tls_syntax.h"
#include <catch.hpp>

using namespace mls;

template<typename T>
T
tls_round_trip(const T& before)
{
  T after;
  tls::unmarshal(tls::marshal(before), after);
  REQUIRE(before == after);
  return after;
}

static const epoch_t epoch_val = 0x01020304;

TEST_CASE("Basic message serialization", "[messages]")
{
  auto random = random_bytes(32);
  auto identity_priv = SignaturePrivateKey::generate();
  auto identity_pub = identity_priv.public_key();
  auto dh_pub = DHPrivateKey::generate().public_key();

  RatchetTree ratchet_tree{ { random, random } };
  auto ratchet_path = ratchet_tree.encrypt(0, random);

  RawKeyCredential cred{ identity_pub };
  Roster roster;
  roster.add(cred);

  UserInitKey user_init_key{
    {},                                       // No ciphersuites
    { DHPrivateKey::generate().public_key() } // Only one init key
  };
  user_init_key.sign(identity_priv);

  GroupInitKey group_init_key{ epoch_val,   3,      { 0x03, 0x03, 0x03, 0x03 },
                               0x0000,      dh_pub, roster,
                               ratchet_tree };

  SECTION("UserInitKey")
  {
    REQUIRE(user_init_key.verify());
    auto after = tls_round_trip(user_init_key);
    REQUIRE(after.verify());
  }

  SECTION("GroupInitKey") { tls_round_trip(group_init_key); }

  SECTION("HandshakeType") { tls_round_trip(HandshakeType::update); }

  SECTION("None") { tls_round_trip(None{}); }

  SECTION("UserAdd") { tls_round_trip(UserAdd{ identity_pub, ratchet_path }); }

  SECTION("GroupAdd")
  {
    tls_round_trip(GroupAdd{ ratchet_path, user_init_key, group_init_key });
  }

  SECTION("Update") { tls_round_trip(Update{ ratchet_path }); }

  SECTION("Remove") { tls_round_trip(Remove{ 0x42, ratchet_path }); }
}

TEST_CASE("Handshake serialization", "[messages]")
{
  uint32_t group_size = 3;
  uint32_t signer_index = 0;
  auto random = random_bytes(32);
  auto identity_priv = SignaturePrivateKey::generate();
  auto identity_pub = identity_priv.public_key();
  auto dh_pub = DHPrivateKey::generate().public_key();

  RatchetTree ratchet_tree{ { random, random } };
  auto ratchet_path = ratchet_tree.encrypt(0, random);

  // Simulate a three-user group
  RawKeyCredential cred{ identity_priv.public_key() };
  Roster roster;
  roster.add(cred);
  roster.add(cred);
  roster.add(cred);

  UserInitKey user_init_key{ {}, { DHPrivateKey::generate().public_key() } };
  user_init_key.sign(identity_priv);

  GroupInitKey group_init_key{ epoch_val,   3,      { 0x03, 0x03, 0x03, 0x03 },
                               0x0000,      dh_pub, roster,
                               ratchet_tree };

  Handshake<None> initial{
    None{}, epoch_val, group_size, signer_index
    // signature omitted
  };

  initial.sign(identity_priv);
  REQUIRE(initial.verify(roster));

  SECTION("None")
  {
    Handshake<None> before{ {}, epoch_val, group_size, signer_index };

    before.sign(identity_priv);
    auto after = tls_round_trip(before);
    REQUIRE(after.verify(roster));
  }

  SECTION("UserAdd")
  {
    Handshake<UserAdd> before{
      { identity_pub, ratchet_path }, epoch_val, group_size, signer_index
    };

    before.sign(identity_priv);
    auto after = tls_round_trip(before);
    REQUIRE(after.verify(roster));
  }

  SECTION("GroupAdd")
  {
    Handshake<GroupAdd> before{ { ratchet_path, user_init_key, group_init_key },
                                epoch_val,
                                group_size,
                                signer_index };

    before.sign(identity_priv);
    auto after = tls_round_trip(before);
    REQUIRE(after.verify(roster));
  }

  SECTION("Update")
  {
    Handshake<Update> before{
      { ratchet_path }, epoch_val, group_size, signer_index
    };

    before.sign(identity_priv);
    auto after = tls_round_trip(before);
    REQUIRE(after.verify(roster));
  }

  SECTION("Remove")
  {
    Handshake<Remove> before{
      { 0x42, ratchet_path }, epoch_val, group_size, signer_index
    };

    before.sign(identity_priv);
    auto after = tls_round_trip(before);
    REQUIRE(after.verify(roster));
  }
}

TEST_CASE("Epoch evolution", "[messages]")
{
  auto first = epoch_val;
  None message;
  auto second = next_epoch(first, message);
  REQUIRE(first != second);

  auto before = epoch_val;
  auto after = tls_round_trip(before);
  REQUIRE(before == after);
}
