#include <doctest/doctest.h>
#include <mls/credential.h>

using namespace mls;

TEST_CASE("Basic Credential")
{
  auto suite = CipherSuite{ CipherSuite::ID::P256_AES128GCM_SHA256_P256 };

  auto user_id = bytes{ 0x00, 0x01, 0x02, 0x03 };
  auto priv = SignaturePrivateKey::generate(suite);
  auto pub = priv.public_key;

  auto cred = Credential::basic(user_id, pub);
  REQUIRE(cred.identity() == user_id);
  REQUIRE(cred.public_key() == pub);
}

TEST_CASE("X509 Credential Depth 2")
{
  // Chain is of depth 2
  const auto issuing_der = from_hex(
    "3081e0308193a00302010202104e40e3b53d3695ab1df21eb08aaaace3300506032b657030"
    "00301e170d3230303932333033303534375a170d3230303932343033303534375a3000302a"
    "300506032b65700321009dc8a19da109e107b76f1c54b76ea2cc21919432507b0a2e012794"
    "5c2e300cb0a3233021300e0603551d0f0101ff0404030202a4300f0603551d130101ff0405"
    "30030101ff300506032b657003410026c17789ceed8e07241a9327a5259dca1caa911a1d26"
    "cf34a0ce4f4723ac6bf0c2777bfceea8288b96232d43dfb3c05dd4cf635d047a5b91ac0310"
    "f85fcf0c0c");
  const auto leaf_der =
    from_hex("3081dd308190a003020102021048d9ffea4d04c0834f07aa7be4388b6e3005060"
             "32b65703000301e170d3230303932333033303534375a170d3230303932343033"
             "303534375a3000302a300506032b657003210071c4972a8780b60044fc04cfa1c"
             "69c35ae0bcf76b76038b486322de0164ac9cfa320301e300e0603551d0f0101ff"
             "0404030202a4300c0603551d130101ff04023000300506032b6570034100eb74f"
             "f02899f2c3bd9dd7a14cdfb0921aa3cdcf57aca4012f5d26158fc4448e1ca7f79"
             "c49908449ee2adf344ad2ebb140bc5f56dea1c34a427a330dcbe512607");

  std::vector<X509Credential::CertData> der_in{ leaf_der, issuing_der };

  auto cred = Credential::x509(der_in);
  CHECK(cred.public_key().data.size() != 0);
}

TEST_CASE("X509 Credential Depth 2 Marshal/Unmarshal")
{
  // Chain is of depth 2
  const auto issuing_der = from_hex(
    "3081e0308193a00302010202104e40e3b53d3695ab1df21eb08aaaace3300506032b657030"
    "00301e170d3230303932333033303534375a170d3230303932343033303534375a3000302a"
    "300506032b65700321009dc8a19da109e107b76f1c54b76ea2cc21919432507b0a2e012794"
    "5c2e300cb0a3233021300e0603551d0f0101ff0404030202a4300f0603551d130101ff0405"
    "30030101ff300506032b657003410026c17789ceed8e07241a9327a5259dca1caa911a1d26"
    "cf34a0ce4f4723ac6bf0c2777bfceea8288b96232d43dfb3c05dd4cf635d047a5b91ac0310"
    "f85fcf0c0c");
  const auto leaf_der =
    from_hex("3081dd308190a003020102021048d9ffea4d04c0834f07aa7be4388b6e3005060"
             "32b65703000301e170d3230303932333033303534375a170d3230303932343033"
             "303534375a3000302a300506032b657003210071c4972a8780b60044fc04cfa1c"
             "69c35ae0bcf76b76038b486322de0164ac9cfa320301e300e0603551d0f0101ff"
             "0404030202a4300c0603551d130101ff04023000300506032b6570034100eb74f"
             "f02899f2c3bd9dd7a14cdfb0921aa3cdcf57aca4012f5d26158fc4448e1ca7f79"
             "c49908449ee2adf344ad2ebb140bc5f56dea1c34a427a330dcbe512607");

  std::vector<X509Credential::CertData> der_in{ leaf_der, issuing_der };

  auto original = Credential::x509(der_in);
  CHECK(original.public_key().data.size() != 0);

  auto marshalled = tls::marshal(original);
  auto unmarshaled = tls::get<Credential>(marshalled);
  CHECK(original.public_key() == unmarshaled.public_key());
}

TEST_CASE("X509 Credential Depth 1 Marshal/Unmarshal")
{
  // Chain is of depth 1
  const auto leaf_der =
    from_hex("3081dd308190a003020102021048d9ffea4d04c0834f07aa7be4388b6e3005060"
             "32b65703000301e170d3230303932333033303534375a170d3230303932343033"
             "303534375a3000302a300506032b657003210071c4972a8780b60044fc04cfa1c"
             "69c35ae0bcf76b76038b486322de0164ac9cfa320301e300e0603551d0f0101ff"
             "0404030202a4300c0603551d130101ff04023000300506032b6570034100eb74f"
             "f02899f2c3bd9dd7a14cdfb0921aa3cdcf57aca4012f5d26158fc4448e1ca7f79"
             "c49908449ee2adf344ad2ebb140bc5f56dea1c34a427a330dcbe512607");

  std::vector<X509Credential::CertData> der_in{ leaf_der };

  auto original = Credential::x509(der_in);
  CHECK(original.public_key().data.size() != 0);

  auto marshalled = tls::marshal(original);
  auto unmarshaled = tls::get<Credential>(marshalled);
  CHECK(original.public_key() == unmarshaled.public_key());
}
