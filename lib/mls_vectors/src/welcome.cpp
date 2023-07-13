#include "common.h"
#include <mls_vectors/mls_vectors.h>

namespace mls_vectors {

using namespace mls;

WelcomeTestVector::WelcomeTestVector(CipherSuite suite)
  : PseudoRandom(suite, "welcome")
  , cipher_suite(suite)
  , init_priv(prg.hpke_key("init_priv"))
{
  auto joiner_secret = prg.secret("joiner_secret");
  auto group_id = prg.secret("group_id");
  auto epoch = epoch_t(prg.uint64("epoch"));
  auto tree_hash = prg.secret("tree_hash");
  auto confirmed_transcript_hash = prg.secret("confirmed_transcript_hash");
  auto enc_priv = prg.hpke_key("enc_priv");
  auto sig_priv = prg.signature_key("sig_priv");
  auto cred = Credential::basic(prg.secret("identity"));

  auto signer_index = LeafIndex{ prg.uint32("signer") };
  auto signer_priv = prg.signature_key("signer_priv");
  signer_pub = signer_priv.public_key;

  auto leaf_node = LeafNode{
    cipher_suite,
    enc_priv.public_key,
    sig_priv.public_key,
    cred,
    Capabilities::create_default(),
    Lifetime::create_default(),
    {},
    sig_priv,
  };
  auto key_package_obj = KeyPackage{
    cipher_suite, init_priv.public_key, leaf_node, {}, sig_priv,
  };
  key_package = key_package_obj;

  auto group_context = GroupContext{
    cipher_suite, group_id, epoch, tree_hash, confirmed_transcript_hash, {}
  };

  auto key_schedule = KeyScheduleEpoch::joiner(
    cipher_suite, joiner_secret, {}, tls::marshal(group_context));
  auto confirmation_tag =
    key_schedule.confirmation_tag(confirmed_transcript_hash);

  auto group_info = GroupInfo{
    group_context,
    {},
    confirmation_tag,
  };
  group_info.sign(signer_index, signer_priv);

  auto welcome_obj = Welcome(cipher_suite, joiner_secret, {}, group_info);
  welcome_obj.encrypt(key_package_obj, std::nullopt);
  welcome = welcome_obj;
}

std::optional<std::string>
WelcomeTestVector::verify() const
{
  VERIFY_EQUAL(
    "kp format", key_package.wire_format(), WireFormat::mls_key_package);
  VERIFY_EQUAL(
    "welcome format", welcome.wire_format(), WireFormat::mls_welcome);

  const auto& key_package_obj = var::get<KeyPackage>(key_package.message);
  const auto& welcome_obj = var::get<Welcome>(welcome.message);

  VERIFY_EQUAL("kp suite", key_package_obj.cipher_suite, cipher_suite);
  VERIFY_EQUAL("welcome suite", welcome_obj.cipher_suite, cipher_suite);

  auto maybe_kpi = welcome_obj.find(key_package_obj);
  VERIFY("found key package", maybe_kpi);

  auto kpi = opt::get(maybe_kpi);
  auto group_secrets = welcome_obj.decrypt_secrets(kpi, init_priv);
  auto group_info = welcome_obj.decrypt(group_secrets.joiner_secret, {});

  // Verify signature on GroupInfo
  VERIFY("group info verify", group_info.verify(signer_pub));

  // Verify confirmation tag
  const auto& group_context = group_info.group_context;
  auto key_schedule = KeyScheduleEpoch::joiner(
    cipher_suite, group_secrets.joiner_secret, {}, tls::marshal(group_context));
  auto confirmation_tag =
    key_schedule.confirmation_tag(group_context.confirmed_transcript_hash);

  return std::nullopt;
}

} // namespace mls_vectors
