#include "messages.h"
#include "tls_syntax.h"
#include <catch.hpp>

using namespace mls;

#define P256_SUITE CipherSuite::P256_SHA256_AES128GCM
#define X25519_SUITE CipherSuite::X25519_SHA256_AES128GCM
#define SIG_TEST SignatureScheme::P256_SHA256

template<typename T>
void
tls_round_trip(const T& before, T& after)
{
  tls::unmarshal(tls::marshal(before), after);
  REQUIRE(before == after);
}

static const epoch_t epoch_val = 0x01020304;

TEST_CASE("Basic message serialization", "[messages]")
{
  auto suite = P256_SUITE;
  auto random = random_bytes(32);
  auto identity_priv = SignaturePrivateKey::generate(SIG_TEST);
  auto identity_pub = identity_priv.public_key();
  auto dh_pub_p256 = DHPrivateKey::generate(P256_SUITE).public_key();
  auto dh_pub_x25519 = DHPrivateKey::generate(X25519_SUITE).public_key();

  RatchetTree ratchet_tree{ P256_SUITE, { random, random } };
  auto ratchet_path = ratchet_tree.encrypt(0, random);

  RawKeyCredential cred{ identity_pub };
  Roster roster;
  roster.add(cred);

  UserInitKey user_init_key;
  user_init_key.add_init_key(dh_pub_p256);
  user_init_key.add_init_key(dh_pub_x25519);
  user_init_key.sign(identity_priv);

  SECTION("UserInitKey")
  {
    REQUIRE(user_init_key.verify());
    UserInitKey after;
    tls_round_trip(user_init_key, after);
    REQUIRE(after.verify());
  }

  SECTION("Welcome")
  {
    Welcome before{ random,       0x42, suite,  roster,
                    ratchet_tree, {},   random, random };
    Welcome after;
    tls_round_trip(before, after);
  }

  SECTION("GroupOperationType")
  {
    GroupOperationType before = GroupOperationType::update;
    GroupOperationType after;
    tls_round_trip(before, after);
  }

  SECTION("Add")
  {
    auto before = Add{ ratchet_path, user_init_key };
    auto after = Add{ P256_SUITE };
    tls_round_trip(before, after);
  }

  SECTION("Update")
  {
    auto before = Update{ ratchet_path };
    auto after = Update{ P256_SUITE };
    tls_round_trip(before, after);
  }

  SECTION("Remove")
  {
    auto before = Remove{ 0x42, ratchet_path };
    auto after = Remove{ P256_SUITE };
    tls_round_trip(before, after);
  }

  SECTION("Handshake")
  {
    auto add = Add{ ratchet_path, user_init_key };
    auto before = Handshake{ 0x42, add, 0x43, random };
    auto after = Handshake{ P256_SUITE };
    tls_round_trip(before, after);
  }
}
