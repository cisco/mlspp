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
  // TODO(rlb@ipv.sx): Continue
  // roster.put(0, cred);
  // REQUIRE(roster.get(0).public_key() == pub);
}
