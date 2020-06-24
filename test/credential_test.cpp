#include "credential.h"
#include <gtest/gtest.h>

using namespace mls;

TEST(CredentialTest, Basic)
{
  auto scheme = SignatureScheme::P256_SHA256;

  auto user_id = bytes{ 0x00, 0x01, 0x02, 0x03 };
  auto priv = SignaturePrivateKey::generate(scheme);
  auto pub = priv.public_key();

  auto cred = Credential::basic(user_id, pub);
  ASSERT_EQ(cred.identity(), user_id);
  ASSERT_EQ(cred.public_key(), pub);
}
