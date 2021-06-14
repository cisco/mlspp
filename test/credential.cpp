#include <doctest/doctest.h>
#include <mls/credential.h>

using namespace mls;

TEST_CASE("Basic Credential")
{
  auto suite = CipherSuite{ CipherSuite::ID::P256_AES128GCM_SHA256_P256 };

  auto user_id = bytes{ 0x00, 0x01, 0x02, 0x03 };
  auto priv = SignaturePrivateKey::generate(suite);
  auto pub = priv.public_key;

  auto cred = Credential::basic(user_id, suite, pub);
  REQUIRE(cred.public_key() == pub);

  const auto& basic = cred.get<BasicCredential>();
  REQUIRE(basic.identity == user_id);
}

TEST_CASE("X509 Credential Depth 2")
{
  // Chain is of depth 2
  const auto issuing_der = from_hex(
    "3081e0308193a003020102021043694a3a0ac4d2f55ca765340f5e3893300506032b657030"
    "00301e170d3230303932333034353632375a170d3230303932343034353632375a3000302a"
    "300506032b657003210088c425c3ef49b8624f6bbf4332931b87b06f7300845b24049ff1c4"
    "824353d385a3233021300e0603551d0f0101ff0404030202a4300f0603551d130101ff0405"
    "30030101ff300506032b6570034100898a5cd71e8236ecfb8abc32d45b4aed3a9daff2c290"
    "cfc8f23546cbf83b87f455ce8ba5e8ddbc4f3b18cde351bcca2f73417e2a0e6c8ca9d723ab"
    "eb0bd9fb06");
  const auto leaf_der =
    from_hex("3081de308191a0030201020211008ab6ec20f45f128ecf9e05d912b5296d30050"
             "6032b65703000301e170d3230303932333034353632375a170d32303039323430"
             "34353632375a3000302a300506032b6570032100fa09d9259d7402e96146229a0"
             "acbba85fd3f9d025981bce36a2e8d0e7d2302bba320301e300e0603551d0f0101"
             "ff0404030202a4300c0603551d130101ff04023000300506032b6570034100305"
             "a1a8c9a1eb85eaf36326ce66aab57bfe62713d2387e00f6af91fe86dffa6fefda"
             "89868e0c280163e33876260a5e8524c39ee592427cad3e99a5539ceae903");

  std::vector<bytes> der_in{ leaf_der, issuing_der };

  auto cred = Credential::x509(der_in);
  CHECK(cred.public_key().data.size() != 0);

  auto x509 = cred.get<X509Credential>();
  const auto& x509_original = cred.get<X509Credential>();
  CHECK(x509.der_chain == x509_original.der_chain);
}

TEST_CASE("X509 Credential Depth 2 Marshal/Unmarshal")
{
  // Chain is of depth 2
  const auto issuing_der = from_hex(
    "3081e0308193a003020102021043694a3a0ac4d2f55ca765340f5e3893300506032b657030"
    "00301e170d3230303932333034353632375a170d3230303932343034353632375a3000302a"
    "300506032b657003210088c425c3ef49b8624f6bbf4332931b87b06f7300845b24049ff1c4"
    "824353d385a3233021300e0603551d0f0101ff0404030202a4300f0603551d130101ff0405"
    "30030101ff300506032b6570034100898a5cd71e8236ecfb8abc32d45b4aed3a9daff2c290"
    "cfc8f23546cbf83b87f455ce8ba5e8ddbc4f3b18cde351bcca2f73417e2a0e6c8ca9d723ab"
    "eb0bd9fb06");
  const auto leaf_der =
    from_hex("3081de308191a0030201020211008ab6ec20f45f128ecf9e05d912b5296d30050"
             "6032b65703000301e170d3230303932333034353632375a170d32303039323430"
             "34353632375a3000302a300506032b6570032100fa09d9259d7402e96146229a0"
             "acbba85fd3f9d025981bce36a2e8d0e7d2302bba320301e300e0603551d0f0101"
             "ff0404030202a4300c0603551d130101ff04023000300506032b6570034100305"
             "a1a8c9a1eb85eaf36326ce66aab57bfe62713d2387e00f6af91fe86dffa6fefda"
             "89868e0c280163e33876260a5e8524c39ee592427cad3e99a5539ceae903");

  std::vector<bytes> der_in{ leaf_der, issuing_der };

  auto original = Credential::x509(der_in);
  CHECK(original.public_key().data.size() != 0);

  auto marshalled = tls::marshal(original);
  auto unmarshaled = tls::get<Credential>(marshalled);
  CHECK(original == unmarshaled);

  auto x509 = unmarshaled.get<X509Credential>();
  const auto& x509_original = original.get<X509Credential>();
  CHECK(x509.der_chain == x509_original.der_chain);
}

TEST_CASE("X509 Credential Depth 1 Marshal/Unmarshal")
{
  // Chain is of depth 1
  const auto leaf_der = from_hex(
    "3081fd3081b0a003020102021100af5442db77d60c749fffe8eebf193afa300506032b6570"
    "3000301e170d3230313132353232333135365a170d3230313132363232333135365a300030"
    "2a300506032b6570032100885cc6836723e204b54275c97928481c55b149e1ed0e22b30d2f"
    "1a89aa24e2d1a33f303d300e0603551d0f0101ff0404030202a4300c0603551d130101ff04"
    "023000301d0603551d110101ff04133011810f7573657240646f6d61696e2e636f6d300506"
    "032b65700341002cc5b3f1a8954ccc872ecddf5779fb007c08ebc869227dec09cfba8fd977"
    "ea49a182a2e51b67d4440d42248f6951f4c765e9e72e301225c953e89b2747129a0c");

  std::vector<bytes> der_in{ { leaf_der } };

  auto original = Credential::x509(der_in);
  CHECK(original.public_key().data.size() != 0);
  auto marshalled = tls::marshal(original);
  auto unmarshaled = tls::get<Credential>(marshalled);
  CHECK(original == unmarshaled);

  auto x509 = unmarshaled.get<X509Credential>();
  const auto& x509_original = original.get<X509Credential>();
  CHECK(x509.der_chain == x509_original.der_chain);
}
