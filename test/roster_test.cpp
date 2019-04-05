#include "roster.h"
#include <gtest/gtest.h>

using namespace mls;

TEST(RosterTest, Basic)
{
  auto scheme = SignatureScheme::P256_SHA256;

  auto user_id = random_bytes(4);
  auto priv = SignaturePrivateKey::generate(scheme);
  auto pub = priv.public_key();

  auto cred = Credential::basic(user_id, priv);
  ASSERT_EQ(cred.identity(), user_id);
  ASSERT_EQ(cred.public_key(), pub);

  Roster roster;
  roster.add(0, cred);
  roster.add(1, cred);
  ASSERT_EQ(roster.size(), 2);
  ASSERT_EQ(roster.get(0), cred);
  ASSERT_EQ(roster.get(1), cred);

  roster.remove(1);
  ASSERT_EQ(roster.size(), 2);
  ASSERT_EQ(roster.get(0), cred);
  ASSERT_THROW(roster.get(1), InvalidParameterError);
}
