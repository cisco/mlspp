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

  SECTION("UserInitKey")
  {
    REQUIRE(user_init_key.verify());
    auto after = tls_round_trip(user_init_key);
    REQUIRE(after.verify());
  }

  SECTION("Welcome")
  {
    Welcome welcome{ random, 0x42, roster, ratchet_tree, {}, dh_pub };
    tls_round_trip(welcome);
  }

  SECTION("GroupOperationType") { tls_round_trip(GroupOperationType::update); }

  SECTION("Add") { tls_round_trip(Add{ ratchet_path, user_init_key }); }

  SECTION("Update") { tls_round_trip(Update{ ratchet_path }); }

  SECTION("Remove") { tls_round_trip(Remove{ 0x42, ratchet_path }); }

  SECTION("Handshake")
  {
    Add add{ ratchet_path, user_init_key };
    tls_round_trip(Handshake{ 0x42, add, 0x43, random });
  }
}
