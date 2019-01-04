#include "roster.h"
#include <gtest/gtest.h>

using namespace mls;

TEST(RosterTest, Basic)
{
  auto scheme = SignatureScheme::P256_SHA256;
  auto priv = SignaturePrivateKey::generate(scheme);
  auto pub = priv.public_key();

  RawKeyCredential cred{ pub };
  ASSERT_EQ(cred.public_key(), pub);

  Roster roster;
  roster.add(cred);
  roster.add(cred);
  ASSERT_EQ(roster.size(), 2);
  ASSERT_EQ(roster.get(0), cred);
  ASSERT_EQ(roster.get(1), cred);

  roster.remove(1);
  ASSERT_EQ(roster.size(), 2);
  ASSERT_EQ(roster.get(0), cred);
  ASSERT_THROW(roster.get(1), InvalidParameterError);
}
