#pragma once

#include <memory>
#include <hpke/signature.h>
#include <bytes/bytes.h>
using namespace bytes_ns;

namespace hpke {

struct Certificate
{

private:
	struct Internals;
	std::unique_ptr<Internals> internals;

public:

	Certificate(const bytes& der);
	Certificate() = delete;
  Certificate(const Certificate& other);
	Certificate(Certificate&& other);
  Certificate& operator=(const Certificate& other);
	~Certificate();

	bool valid_from(const Certificate& parent);

	const Signature::ID public_key_algorithm;
	//const Signature::PublicKey public_key;
	const bytes raw;
};

} // namespace hpke
