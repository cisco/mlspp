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
	const auto issuing_der = from_hex("3081e0308193a003020102021043694a3a0ac4d2f55ca765340f5e3893300506032b65703000301e170d3230303932333034353632375a170d3230303932343034353632375a3000302a300506032b657003210088c425c3ef49b8624f6bbf4332931b87b06f7300845b24049ff1c4824353d385a3233021300e0603551d0f0101ff0404030202a4300f0603551d130101ff040530030101ff300506032b6570034100898a5cd71e8236ecfb8abc32d45b4aed3a9daff2c290cfc8f23546cbf83b87f455ce8ba5e8ddbc4f3b18cde351bcca2f73417e2a0e6c8ca9d723abeb0bd9fb06");
	const auto leaf_der = from_hex("3081de308191a0030201020211008ab6ec20f45f128ecf9e05d912b5296d300506032b65703000301e170d3230303932333034353632375a170d3230303932343034353632375a3000302a300506032b6570032100fa09d9259d7402e96146229a0acbba85fd3f9d025981bce36a2e8d0e7d2302bba320301e300e0603551d0f0101ff0404030202a4300c0603551d130101ff04023000300506032b6570034100305a1a8c9a1eb85eaf36326ce66aab57bfe62713d2387e00f6af91fe86dffa6fefda89868e0c280163e33876260a5e8524c39ee592427cad3e99a5539ceae903");

	std::vector<X509Credential::CertData> der_in{ leaf_der, issuing_der };

  auto cred = Credential::x509(der_in);
  CHECK(cred.public_key().data.size() != 0);
}

TEST_CASE("X509 Credential Depth 2 Marshal/Unmarshal")
{
  // Chain is of depth 2
	const auto issuing_der = from_hex("3081e0308193a003020102021043694a3a0ac4d2f55ca765340f5e3893300506032b65703000301e170d3230303932333034353632375a170d3230303932343034353632375a3000302a300506032b657003210088c425c3ef49b8624f6bbf4332931b87b06f7300845b24049ff1c4824353d385a3233021300e0603551d0f0101ff0404030202a4300f0603551d130101ff040530030101ff300506032b6570034100898a5cd71e8236ecfb8abc32d45b4aed3a9daff2c290cfc8f23546cbf83b87f455ce8ba5e8ddbc4f3b18cde351bcca2f73417e2a0e6c8ca9d723abeb0bd9fb06");
	const auto leaf_der = from_hex("3081de308191a0030201020211008ab6ec20f45f128ecf9e05d912b5296d300506032b65703000301e170d3230303932333034353632375a170d3230303932343034353632375a3000302a300506032b6570032100fa09d9259d7402e96146229a0acbba85fd3f9d025981bce36a2e8d0e7d2302bba320301e300e0603551d0f0101ff0404030202a4300c0603551d130101ff04023000300506032b6570034100305a1a8c9a1eb85eaf36326ce66aab57bfe62713d2387e00f6af91fe86dffa6fefda89868e0c280163e33876260a5e8524c39ee592427cad3e99a5539ceae903");

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
	const auto leaf_der = from_hex("3081de308191a0030201020211008ab6ec20f45f128ecf9e05d912b5296d300506032b65703000301e170d3230303932333034353632375a170d3230303932343034353632375a3000302a300506032b6570032100fa09d9259d7402e96146229a0acbba85fd3f9d025981bce36a2e8d0e7d2302bba320301e300e0603551d0f0101ff0404030202a4300c0603551d130101ff04023000300506032b6570034100305a1a8c9a1eb85eaf36326ce66aab57bfe62713d2387e00f6af91fe86dffa6fefda89868e0c280163e33876260a5e8524c39ee592427cad3e99a5539ceae903");

	std::vector<X509Credential::CertData> der_in{ leaf_der };

  auto original = Credential::x509(der_in);
  CHECK(original.public_key().data.size() != 0);

  auto marshalled = tls::marshal(original);
  auto unmarshaled = tls::get<Credential>(marshalled);
  CHECK(original.public_key() == unmarshaled.public_key());
}
