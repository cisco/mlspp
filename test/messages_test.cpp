#include "messages.h"
#include "test_vectors.h"
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

void
tls_round_trip_all(const MessagesTestVectors::TestCase& test_case)
{
  UserInitKey user_init_key;
  tls_round_trip(test_case.user_init_key, user_init_key);

  WelcomeInfo welcome_info{ test_case.cipher_suite };
  tls_round_trip(test_case.welcome_info, welcome_info);

  Welcome welcome;
  tls_round_trip(test_case.welcome, welcome);

  Handshake add{ test_case.cipher_suite };
  tls_round_trip(test_case.add, add);

  Handshake update{ test_case.cipher_suite };
  tls_round_trip(test_case.update, update);

  Handshake remove{ test_case.cipher_suite };
  tls_round_trip(test_case.remove, remove);
}

static const epoch_t epoch_val = 0x01020304;

class MessagesTest : public ::testing::Test
{
protected:
  const TestVectors& tv;

  // NB: Successful parsing of the test vectors is validated by the
  // fact that this method doesn't throw.
  MessagesTest()
    : tv(TestVectors::get())
  {}
};

TEST_F(MessagesTest, UserInitKey)
{
  UserInitKey after;
  tls_round_trip(tv.messages.user_init_key_all, after);
}

TEST_F(MessagesTest, Suite_P256_P256)
{
  tls_round_trip_all(tv.messages.case_p256_p256);
}

TEST_F(MessagesTest, Suite_X25519_Ed25519)
{
  tls_round_trip_all(tv.messages.case_x25519_ed25519);
}

TEST_F(MessagesTest, Suite_P521_P521)
{
  tls_round_trip_all(tv.messages.case_p521_p521);
}

TEST_F(MessagesTest, Suite_X448_Ed448)
{
  tls_round_trip_all(tv.messages.case_x448_ed448);
}
