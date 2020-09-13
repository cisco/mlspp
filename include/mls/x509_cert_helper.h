#pragma once
#include "bytes/bytes.h"
#include <memory>

using namespace std;
using namespace bytes_ns;

namespace mls {

// TODO: move this inside X509Certificate to not mess up global space
enum struct SignatureAlgorithm : uint16_t {
	unknown = 0x0000,
	ED25519 = 0x0001,
	ED448 = 0x0002,
};

struct X509Certificate {

	static std::unique_ptr<X509Certificate> get(const bytes& cert_in);

	virtual ~X509Certificate() = default;

  virtual bool verify() const = 0;

  virtual bytes public_key() const = 0;

  virtual bytes subject_name() const = 0;

};

}
