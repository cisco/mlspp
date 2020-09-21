#include <doctest/doctest.h>
#include <iostream>
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
	const auto leaf_der = from_hex("3081de308191a00302010202110089f2d252744135d5f3f005f1edc609d2300506032b65703000301e170d3230303932313036333230345a170d3230303932323036333230345a3000302a300506032b65700321009d28cb0fdb2da572066ba1c90dedbf8010ba85fba4bffa8fffe67e26d5515252a320301e300e0603551d0f0101ff0404030202a4300c0603551d130101ff04023000300506032b6570034100b59e47d1f9de4d595ca2d0a2a1dbc6a59eacfa3e5958d315d3809d6f7abba0474643a620e81b91ec987b30214a30818f97e47f21ad15d3b304a6ebf142b36105");
	const auto issuing_der = from_hex("3081e1308194a003020102021100d9443a777704afc9df1ef0dabd328e6e300506032b65703000301e170d3230303932313036333230345a170d3230303932323036333230345a3000302a300506032b65700321009f3fea85d329dd340cba5f7b9655b79af89784a658509a50c2eec63a3e3c3a3ba3233021300e0603551d0f0101ff0404030202a4300f0603551d130101ff040530030101ff300506032b657003410059fe72402a0431fdcf97cb0cd72bbb902c5cb0f1f0ad6b14c1cb6127bf2c55a27bf929113bbfb18162cecad5b511eae910e22fedf7756726f03cf6f9382fef0e");
	std::vector<bytes> der_in(2);
	der_in[0] = leaf_der;
	der_in[1] = issuing_der;

  auto cred = Credential::x509(der_in);
  CHECK(cred.public_key().data.size() != 0);
}

TEST_CASE("X509 Credential Depth 2 Marshal/Unmarshal")
{
	// Chain is of depth 2
	const auto leaf_der = from_hex("3081de308191a00302010202110089f2d252744135d5f3f005f1edc609d2300506032b65703000301e170d3230303932313036333230345a170d3230303932323036333230345a3000302a300506032b65700321009d28cb0fdb2da572066ba1c90dedbf8010ba85fba4bffa8fffe67e26d5515252a320301e300e0603551d0f0101ff0404030202a4300c0603551d130101ff04023000300506032b6570034100b59e47d1f9de4d595ca2d0a2a1dbc6a59eacfa3e5958d315d3809d6f7abba0474643a620e81b91ec987b30214a30818f97e47f21ad15d3b304a6ebf142b36105");
	const auto issuing_der = from_hex("3081e1308194a003020102021100d9443a777704afc9df1ef0dabd328e6e300506032b65703000301e170d3230303932313036333230345a170d3230303932323036333230345a3000302a300506032b65700321009f3fea85d329dd340cba5f7b9655b79af89784a658509a50c2eec63a3e3c3a3ba3233021300e0603551d0f0101ff0404030202a4300f0603551d130101ff040530030101ff300506032b657003410059fe72402a0431fdcf97cb0cd72bbb902c5cb0f1f0ad6b14c1cb6127bf2c55a27bf929113bbfb18162cecad5b511eae910e22fedf7756726f03cf6f9382fef0e");
	std::vector<bytes> der_in(2);
	der_in[0] = leaf_der;
	der_in[1] = issuing_der;

	auto actual = Credential::x509(der_in);
	CHECK(actual.public_key().data.size() != 0);

	auto marshalled = tls::marshal(actual);
	Credential expected;
	tls::unmarshal(marshalled, expected);
	CHECK(actual.public_key() == expected.public_key());
}

TEST_CASE("X509 Credential Depth 1 Marshal/Unmarshal")
{
	// Chain is of depth 1
	const auto leaf_der = from_hex("3081de308191a00302010202110089f2d252744135d5f3f005f1edc609d2300506032b65703000301e170d3230303932313036333230345a170d3230303932323036333230345a3000302a300506032b65700321009d28cb0fdb2da572066ba1c90dedbf8010ba85fba4bffa8fffe67e26d5515252a320301e300e0603551d0f0101ff0404030202a4300c0603551d130101ff04023000300506032b6570034100b59e47d1f9de4d595ca2d0a2a1dbc6a59eacfa3e5958d315d3809d6f7abba0474643a620e81b91ec987b30214a30818f97e47f21ad15d3b304a6ebf142b36105");
	std::vector<bytes> der_in(1);
	der_in[0] = leaf_der;

	auto actual = Credential::x509(der_in);
	CHECK(actual.public_key().data.size() != 0);

	auto marshalled = tls::marshal(actual);
	Credential expected;
	tls::unmarshal(marshalled, expected);
	CHECK(actual.public_key() == expected.public_key());
}

