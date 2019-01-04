#include "messages.h"
#include "tls_syntax.h"
#include <gtest/gtest.h>

using namespace mls;

template<typename T>
void
tls_round_trip(const T& before, T& after)
{
  tls::unmarshal(tls::marshal(before), after);
  ASSERT_EQ(before, after);
}

static const epoch_t epoch_val = 0x01020304;

class MessagesTest : public ::testing::Test {
protected:
  const CipherSuite suite = CipherSuite::P256_SHA256_AES128GCM;
  const SignatureScheme scheme = SignatureScheme::P256_SHA256;

  bytes random;
  UserInitKey user_init_key;
  Roster roster;
  RatchetTree ratchet_tree;
  DirectPath direct_path;

  MessagesTest()
    : random(random_bytes(32))
    , ratchet_tree(suite)
    , direct_path(suite)
  {
    auto identity_priv = SignaturePrivateKey::generate(scheme);
    auto identity_pub = identity_priv.public_key();

    auto p256 = CipherSuite::P256_SHA256_AES128GCM;
    auto x25519 = CipherSuite::X25519_SHA256_AES128GCM;
    auto dh_pub_p256 = DHPrivateKey::generate(p256).public_key();
    auto dh_pub_x25519 = DHPrivateKey::generate(x25519).public_key();

    ratchet_tree = RatchetTree{ suite, { random, random } };
    direct_path = ratchet_tree.encrypt(0, random);

    RawKeyCredential cred{ identity_pub };
    roster.add(cred);

    user_init_key.add_init_key(dh_pub_p256);
    user_init_key.add_init_key(dh_pub_x25519);
    user_init_key.sign(identity_priv);
  }
};

TEST_F(MessagesTest, UserInitKey)
{
  ASSERT_TRUE(user_init_key.verify());
  UserInitKey after;
  tls_round_trip(user_init_key, after);
  ASSERT_TRUE(after.verify());
}

TEST_F(MessagesTest, Welcome)
{
  Welcome before{ random,       0x42, suite,  roster,
                  ratchet_tree, {},   random };
  Welcome after;
  tls_round_trip(before, after);
}

TEST_F(MessagesTest, GroupOperationType)
{
  GroupOperationType before = GroupOperationType::update;
  GroupOperationType after;
  tls_round_trip(before, after);
}

TEST_F(MessagesTest, Add)
{
  auto before = Add{ user_init_key };
  auto after = Add{};
  tls_round_trip(before, after);
}

TEST_F(MessagesTest, Update)
{
  auto before = Update{ direct_path };
  auto after = Update{ suite };
  tls_round_trip(before, after);
}

TEST_F(MessagesTest, Remove)
{
  auto before = Remove{ 0x42, direct_path };
  auto after = Remove{ suite };
  tls_round_trip(before, after);
}

TEST_F(MessagesTest, Handshake)
{
  auto add = Add{ user_init_key };
  auto before = Handshake{ 0x42, add, 0x43, random };
  auto after = Handshake{ suite };
  tls_round_trip(before, after);
}
