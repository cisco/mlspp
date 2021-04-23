#include <hpke/hpke.h>
#include <hpke/signature.h>
using namespace hpke;

#include <bytes/bytes.h>
using namespace bytes_ns;

void
ensure_fips_if_required();

const Signature&
select_signature(Signature::ID id);

const KEM&
select_kem(KEM::ID id);

const KDF&
select_kdf(KDF::ID id);

const AEAD&
select_aead(AEAD::ID id);
