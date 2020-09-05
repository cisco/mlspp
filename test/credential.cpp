#include <doctest/doctest.h>
#include <mls/credential.h>

using namespace mls;

TEST_CASE("Basic Credential")
{
  auto suite = CipherSuite(CipherSuite::ID::P256_AES128GCM_SHA256_P256);

  auto user_id = bytes{ 0x00, 0x01, 0x02, 0x03 };
  auto priv = SignaturePrivateKey::generate(suite);
  auto pub = priv.public_key();

  auto cred = Credential::basic(user_id, pub);
  REQUIRE(cred.identity() == user_id);
  REQUIRE(cred.public_key() == pub);
}
