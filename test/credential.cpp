#include <catch2/catch_all.hpp>
#include <mls/credential.h>

using namespace MLS_NAMESPACE;

TEST_CASE("Basic Credential")
{
  auto suite = CipherSuite{ CipherSuite::ID::P256_AES128GCM_SHA256_P256 };

  auto user_id = bytes{ 0x00, 0x01, 0x02, 0x03 };
  auto priv = SignaturePrivateKey::generate(suite);
  auto pub = priv.public_key;

  auto cred = Credential::basic(user_id);
  REQUIRE(cred.valid_for(pub));

  const auto& basic = cred.get<BasicCredential>();
  REQUIRE(basic.identity == user_id);
}

TEST_CASE("X.509 Credential")
{
  auto suite = CipherSuite{ CipherSuite::ID::P256_AES128GCM_SHA256_P256 };

  const auto priv_data = from_hex(
    "afdee46291cd304277fdd2599f125c4cc0aa1e539df7fd7c8032f632c5d0d3a4");

  const auto leaf_der =
    from_hex("308201363081dda003020102020100300a06082a8648ce3d0403023014311230"
             "100603550403130946616b6520434120303020170d3233303730313138353334"
             "385a180f32313232303630393138353334385a30123110300e06035504031307"
             "5375626a6563743059301306072a8648ce3d020106082a8648ce3d0301070342"
             "00041dd062efebc93e62c8c5a4984e6a1df6192ae87eaea0666e4fc5ff8d610c"
             "2e465d077fafd72e249ce5ba602188df4203b78422380239bbcb9ab88b6940ba"
             "f6a8a320301e300e0603551d0f0101ff0404030202a4300c0603551d130101ff"
             "04023000300a06082a8648ce3d0403020348003045022041d8341e498806ec4b"
             "7aa097deaeffe6b752ecc49e5093ad0d2ffba7ca629eee0221009f24accf35a9"
             "05dcd8720ad6dfa881e7614f3b6abd9f49ebf21e2439060402eb");

  auto priv = SignaturePrivateKey::parse(suite, priv_data);
  auto pub = priv.public_key;

  auto cred = Credential::x509({ leaf_der });
  REQUIRE(cred.valid_for(pub));

  const auto& x509 = cred.get<X509Credential>();
  REQUIRE(x509.der_chain.size() == 1);
  REQUIRE(x509.der_chain.front().data == leaf_der);
}

TEST_CASE("Multi Credential")
{
  auto suite = CipherSuite{ CipherSuite::ID::P256_AES128GCM_SHA256_P256 };

  // First X.509 Credential
  const auto leaf_der_1 =
    from_hex("308201363081dda003020102020100300a06082a8648ce3d0403023014311230"
             "100603550403130946616b6520434120303020170d3233303730313138353334"
             "385a180f32313232303630393138353334385a30123110300e06035504031307"
             "5375626a6563743059301306072a8648ce3d020106082a8648ce3d0301070342"
             "00041dd062efebc93e62c8c5a4984e6a1df6192ae87eaea0666e4fc5ff8d610c"
             "2e465d077fafd72e249ce5ba602188df4203b78422380239bbcb9ab88b6940ba"
             "f6a8a320301e300e0603551d0f0101ff0404030202a4300c0603551d130101ff"
             "04023000300a06082a8648ce3d0403020348003045022041d8341e498806ec4b"
             "7aa097deaeffe6b752ecc49e5093ad0d2ffba7ca629eee0221009f24accf35a9"
             "05dcd8720ad6dfa881e7614f3b6abd9f49ebf21e2439060402eb");
  const auto cred_priv_data_1 = from_hex(
    "afdee46291cd304277fdd2599f125c4cc0aa1e539df7fd7c8032f632c5d0d3a4");

  auto cred_priv_1 = SignaturePrivateKey::parse(suite, cred_priv_data_1);
  auto cred_pub_1 = cred_priv_1.public_key;

  auto cred_1 = Credential::x509({ leaf_der_1 });
  REQUIRE(cred_1.valid_for(cred_pub_1));

  // Second X.509 Credential
  const auto leaf_der_2 =
    from_hex("308201353081dda003020102020100300a06082a8648ce3d0403023014311230"
             "100603550403130946616b6520434120303020170d3233303730313139303234"
             "305a180f32313232303630393139303234305a30123110300e06035504031307"
             "5375626a6563743059301306072a8648ce3d020106082a8648ce3d0301070342"
             "0004e7f7987f024d0d1b420018a585929e690f95b6fe7b23ec1ff6532b1c55c4"
             "75ef36b826e4b54bd60b8823f3fc222c28369771a9ed0a644df351e16ad495dc"
             "fb54a320301e300e0603551d0f0101ff0404030202a4300c0603551d130101ff"
             "04023000300a06082a8648ce3d040302034700304402200d7e0e5362cfe4d551"
             "cbb6a5b2b64541e30e86e10e734e84c1e24b46d1e098bc022037fc32a59b4062"
             "c14b3323a20a0c7a5e05bbd3f27e22dc225ddd69ca771b90fc");
  const auto cred_priv_data_2 = from_hex(
    "8915f49863cb24d6553fab0036da18a0fec431ae0cc94255010f6ed35555631e");

  auto cred_priv_2 = SignaturePrivateKey::parse(suite, cred_priv_data_2);
  auto cred_pub_2 = cred_priv_2.public_key;

  auto cred_2 = Credential::x509({ leaf_der_2 });
  REQUIRE(cred_2.valid_for(cred_pub_2));

  // Multi-Credential
  auto priv = SignaturePrivateKey::generate(suite);
  auto pub = priv.public_key;

  auto cred = Credential::multi(
    { { suite, cred_1, cred_priv_1 }, { suite, cred_2, cred_priv_2 } }, pub);
  REQUIRE(cred.valid_for(pub));

  const auto& multi = cred.get<MultiCredential>();
  const auto& bindings = multi.bindings;
  REQUIRE(bindings.size() == 2);
  REQUIRE(bindings[0].credential == cred_1);
  REQUIRE(bindings[0].credential_key == cred_pub_1);
  REQUIRE(bindings[0].credential.valid_for(bindings[0].credential_key));
  REQUIRE(bindings[1].credential == cred_2);
  REQUIRE(bindings[1].credential_key == cred_pub_2);
  REQUIRE(bindings[1].credential.valid_for(bindings[1].credential_key));
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

  const std::vector<bytes> der_in{ leaf_der, issuing_der };

  auto cred = Credential::x509(der_in);
  auto x509 = cred.get<X509Credential>();
  CHECK(!x509.public_key().data.empty());

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

  const std::vector<bytes> der_in{ leaf_der, issuing_der };

  auto original = Credential::x509(der_in);
  const auto& x509_original = original.get<X509Credential>();
  CHECK(!x509_original.public_key().data.empty());

  auto marshalled = tls::marshal(original);
  auto unmarshaled = tls::get<Credential>(marshalled);
  CHECK(original == unmarshaled);

  auto x509_unmarshaled = unmarshaled.get<X509Credential>();
  CHECK(x509_unmarshaled.der_chain == x509_original.der_chain);
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

  const std::vector<bytes> der_in{ { leaf_der } };

  auto original = Credential::x509(der_in);
  auto x509_original = original.get<X509Credential>();
  CHECK(!x509_original.public_key().data.empty());

  auto marshalled = tls::marshal(original);
  auto unmarshaled = tls::get<Credential>(marshalled);
  CHECK(original == unmarshaled);

  auto x509_unmarshaled = unmarshaled.get<X509Credential>();
  CHECK(x509_unmarshaled.der_chain == x509_original.der_chain);
}
