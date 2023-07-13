#include "common.h"
#include <mls_vectors/mls_vectors.h>

namespace mls_vectors {

using namespace mls;

static std::vector<PSKWithSecret>
to_psk_w_secret(const std::vector<PSKSecretTestVector::PSK>& psks)
{
  auto pskws = std::vector<PSKWithSecret>(psks.size());
  std::transform(
    std::begin(psks), std::end(psks), std::begin(pskws), [](const auto& psk) {
      auto ext_id = ExternalPSK{ psk.psk_id };
      auto id = PreSharedKeyID{ ext_id, psk.psk_nonce };
      return PSKWithSecret{ id, psk.psk };
    });

  return pskws;
}

PSKSecretTestVector::PSKSecretTestVector(mls::CipherSuite suite, size_t n_psks)
  : PseudoRandom(suite, "psk_secret")
  , cipher_suite(suite)
  , psks(n_psks)
{
  uint32_t i = 0;
  for (auto& psk : psks) {
    auto ix = to_hex(tls::marshal(i));
    i += 1;

    psk.psk_id = prg.secret("psk_id" + ix);
    psk.psk_nonce = prg.secret("psk_nonce" + ix);
    psk.psk = prg.secret("psk" + ix);
  }

  psk_secret =
    KeyScheduleEpoch::make_psk_secret(cipher_suite, to_psk_w_secret(psks));
}

std::optional<std::string>
PSKSecretTestVector::verify() const
{
  auto actual =
    KeyScheduleEpoch::make_psk_secret(cipher_suite, to_psk_w_secret(psks));
  VERIFY_EQUAL("psk secret", actual, psk_secret);

  return std::nullopt;
}

} // namespace mls_vectors
