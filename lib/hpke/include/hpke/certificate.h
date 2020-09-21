#pragma once

#include <bytes/bytes.h>
#include <hpke/signature.h>
#include <memory>
using namespace bytes_ns;

namespace hpke {

struct Certificate
{

private:
  struct ParsedCertificate;
  std::unique_ptr<ParsedCertificate> parsed_cert;

public:
	struct X509Signature {
		enum struct ID : uint16_t
		{
			unknown = 0x0000,
			Ed25519 = 0x0001,
			Ed448 = 0x0002,
		};

		struct PublicKey {
			bytes data;
		};
	};


	Certificate() = delete;
  explicit Certificate(const bytes& der);
  Certificate(const Certificate& other);
  Certificate& operator=(const Certificate& other);
  Certificate(Certificate&& other) noexcept;
  ~Certificate();

  // TODO not supported yet.
  // bool valid_from(const Certificate& parent);

  const X509Signature::ID public_key_algorithm;
  const X509Signature::PublicKey public_key;
  const bytes raw;
};

} // namespace hpke
