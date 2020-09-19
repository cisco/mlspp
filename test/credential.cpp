#include <doctest/doctest.h>
#include <fstream>
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


std::vector<std::string>
read_hex_file(const std::string& filename)
{
	std::ifstream f(filename, std::ios::in);
	std::vector<std::string> lines;
	if (f.is_open()) {
		std::string l;
		while (getline(f, l)) {
			lines.push_back(l);
		}
		f.close();
	} else {
		throw std::system_error(
						errno, std::system_category(), "failed to open " + filename);
	}
	return lines;
}

TEST_CASE("X509 Credential Depth ")
{

	// Chain is of depth 2
	const std::string cert_bundle = "../../scripts/cert_bundle.bin";
	auto certs = read_hex_file(cert_bundle);
	CHECK(certs.size() == 2);

	std::vector<bytes> der_in(certs.size());
	for(size_t i = 0; i < certs.size(); i++) {
		der_in[i] = from_hex(certs[i]);
	}

	auto cred = Credential::x509(der_in);
	CHECK(cred.public_key().data.size() != 0);
}