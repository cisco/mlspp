#include "credential.h"
#include <gtest/gtest.h>

using namespace mls;

TEST(CredentialTest, Basic)
{
  auto scheme = SignatureScheme::P256_SHA256;

  auto user_id = random_bytes(4);
  auto priv = SignaturePrivateKey::generate(scheme);
  auto pub = priv.public_key();

  auto cred = Credential::basic(user_id, priv);
  ASSERT_EQ(cred.identity(), user_id);
  ASSERT_EQ(cred.public_key(), pub);
}
