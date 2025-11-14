#include <hpke/hpke.h>
#include <hpke/signature.h>
using namespace MLS_NAMESPACE::hpke;

#include <bytes/bytes.h>
using namespace MLS_NAMESPACE::bytes_ns;

void
ensure_fips_if_required();

bool
fips();
bool
fips_disable(AEAD::ID id);
bool
fips_disable(Signature::ID id);

const Signature&
select_signature(Signature::ID id);

bool
supported_kem(KEM::ID id);

bool
supported_kdf(KDF::ID id);

bool
supported_aead(AEAD::ID id);

bool
supported(KEM::ID kem, KDF::ID kdf, AEAD::ID aead);

const KEM&
select_kem(KEM::ID id);

const KDF&
select_kdf(KDF::ID id);

const AEAD&
select_aead(AEAD::ID id);
