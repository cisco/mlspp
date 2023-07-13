#include <mls/state.h>
#include <mls_vectors/mls_vectors.h>

#include "common.h"

namespace mls_vectors {

using namespace mls;

MessagesTestVector::MessagesTestVector()
  : PseudoRandom(CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519, "messages")
{
  auto suite = CipherSuite{ CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519 };
  auto epoch = epoch_t(prg.uint64("epoch"));
  auto index = LeafIndex{ prg.uint32("index") };
  auto user_id = prg.secret("user_id");
  auto group_id = prg.secret("group_id");

  auto app_id_ext = ApplicationIDExtension{ prg.secret("app_id") };
  auto ext_list = ExtensionList{};
  ext_list.add(app_id_ext);

  auto group_context = GroupContext{ suite,
                                     group_id,
                                     epoch,
                                     prg.secret("tree_hash"),
                                     prg.secret("confirmed_trasncript_hash"),
                                     ext_list };

  auto version = ProtocolVersion::mls10;
  auto hpke_priv = prg.hpke_key("hpke_priv");
  auto hpke_pub = hpke_priv.public_key;
  auto hpke_ct =
    HPKECiphertext{ prg.secret("kem_output"), prg.secret("ciphertext") };
  auto sig_priv = prg.signature_key("signature_priv");
  auto sig_pub = sig_priv.public_key;

  // KeyPackage and extensions
  auto cred = Credential::basic(user_id);
  auto leaf_node = LeafNode{ suite,
                             hpke_pub,
                             sig_pub,
                             cred,
                             Capabilities::create_default(),
                             Lifetime::create_default(),
                             ext_list,
                             sig_priv };
  auto key_package_obj = KeyPackage{ suite, hpke_pub, leaf_node, {}, sig_priv };

  auto leaf_node_update =
    leaf_node.for_update(suite, group_id, index, hpke_pub, {}, sig_priv);
  auto leaf_node_commit = leaf_node.for_commit(
    suite, group_id, index, hpke_pub, prg.secret("parent_hash"), {}, sig_priv);

  auto sender = Sender{ MemberSender{ index } };

  auto tree = TreeKEMPublicKey{ suite };
  tree.add_leaf(leaf_node);
  tree.add_leaf(leaf_node);
  auto ratchet_tree_obj = RatchetTreeExtension{ tree };

  // Welcome and its substituents
  auto group_info_obj =
    GroupInfo{ group_context, ext_list, prg.secret("confirmation_tag") };
  auto joiner_secret = prg.secret("joiner_secret");
  auto path_secret = prg.secret("path_secret");
  auto psk_id = ExternalPSK{ prg.secret("psk_id") };
  auto psk_nonce = prg.secret("psk_nonce");
  auto group_secrets_obj = GroupSecrets{ joiner_secret,
                                         { { path_secret } },
                                         PreSharedKeys{ {
                                           { psk_id, psk_nonce },
                                         } } };
  auto welcome_obj = Welcome{ suite, joiner_secret, {}, group_info_obj };
  welcome_obj.encrypt(key_package_obj, path_secret);

  // Proposals
  auto add = Add{ key_package_obj };
  auto update = Update{ leaf_node_update };
  auto remove = Remove{ index };
  auto pre_shared_key = PreSharedKey{ psk_id, psk_nonce };
  auto reinit = ReInit{ group_id, version, suite, {} };
  auto external_init = ExternalInit{ prg.secret("external_init") };

  // Commit
  auto proposal_ref = ProposalRef{ 32, 0xa0 };

  auto commit_obj = Commit{ {
                              { proposal_ref },
                              { Proposal{ add } },
                            },
                            UpdatePath{
                              leaf_node_commit,
                              {
                                { hpke_pub, { hpke_ct, hpke_ct } },
                                { hpke_pub, { hpke_ct, hpke_ct, hpke_ct } },
                              },
                            } };

  // AuthenticatedContent with Application / Proposal / Commit

  // PublicMessage
  auto membership_key = prg.secret("membership_key");

  auto content_auth_proposal = AuthenticatedContent::sign(
    WireFormat::mls_plaintext,
    { group_id, epoch, sender, {}, Proposal{ remove } },
    suite,
    sig_priv,
    group_context);
  auto public_message_proposal_obj = PublicMessage::protect(
    content_auth_proposal, suite, membership_key, group_context);

  auto content_auth_commit =
    AuthenticatedContent::sign(WireFormat::mls_plaintext,
                               { group_id, epoch, sender, {}, commit_obj },
                               suite,
                               sig_priv,
                               group_context);
  content_auth_commit.set_confirmation_tag(prg.secret("confirmation_tag"));
  auto public_message_commit_obj = PublicMessage::protect(
    content_auth_commit, suite, membership_key, group_context);

  // PrivateMessage
  auto content_auth_application_obj = AuthenticatedContent::sign(
    WireFormat::mls_ciphertext,
    { group_id, epoch, sender, {}, ApplicationData{} },
    suite,
    sig_priv,
    group_context);

  auto keys = GroupKeySource(
    suite, LeafCount{ index.val + 1 }, prg.secret("encryption_secret"));
  auto private_message_obj =
    PrivateMessage::protect(content_auth_application_obj,
                            suite,
                            keys,
                            prg.secret("sender_data_secret"),
                            10);

  // Serialize out all the objects
  mls_welcome = tls::marshal(MLSMessage{ welcome_obj });
  mls_group_info = tls::marshal(MLSMessage{ group_info_obj });
  mls_key_package = tls::marshal(MLSMessage{ key_package_obj });

  ratchet_tree = tls::marshal(ratchet_tree_obj);
  group_secrets = tls::marshal(group_secrets_obj);

  add_proposal = tls::marshal(add);
  update_proposal = tls::marshal(update);
  remove_proposal = tls::marshal(remove);
  pre_shared_key_proposal = tls::marshal(pre_shared_key);
  re_init_proposal = tls::marshal(reinit);
  external_init_proposal = tls::marshal(external_init);

  commit = tls::marshal(commit_obj);

  public_message_proposal =
    tls::marshal(MLSMessage{ public_message_proposal_obj });
  public_message_commit = tls::marshal(MLSMessage{ public_message_commit_obj });
  private_message = tls::marshal(MLSMessage{ private_message_obj });
}

std::optional<std::string>
MessagesTestVector::verify() const
{
  // TODO(RLB) Verify signatures
  // TODO(RLB) Verify content types in PublicMessage objects
  auto require_format = [](WireFormat format) {
    return
      [format](const MLSMessage& msg) { return msg.wire_format() == format; };
  };

  VERIFY_TLS_RTT_VAL("Welcome",
                     MLSMessage,
                     mls_welcome,
                     require_format(WireFormat::mls_welcome));
  VERIFY_TLS_RTT_VAL("GroupInfo",
                     MLSMessage,
                     mls_group_info,
                     require_format(WireFormat::mls_group_info));
  VERIFY_TLS_RTT_VAL("KeyPackage",
                     MLSMessage,
                     mls_key_package,
                     require_format(WireFormat::mls_key_package));

  VERIFY_TLS_RTT("RatchetTree", RatchetTreeExtension, ratchet_tree);
  VERIFY_TLS_RTT("GroupSecrets", GroupSecrets, group_secrets);

  VERIFY_TLS_RTT("Add", Add, add_proposal);
  VERIFY_TLS_RTT("Update", Update, update_proposal);
  VERIFY_TLS_RTT("Remove", Remove, remove_proposal);
  VERIFY_TLS_RTT("PreSharedKey", PreSharedKey, pre_shared_key_proposal);
  VERIFY_TLS_RTT("ReInit", ReInit, re_init_proposal);
  VERIFY_TLS_RTT("ExternalInit", ExternalInit, external_init_proposal);

  VERIFY_TLS_RTT("Commit", Commit, commit);

  VERIFY_TLS_RTT_VAL("Public(Proposal)",
                     MLSMessage,
                     public_message_proposal,
                     require_format(WireFormat::mls_plaintext));
  VERIFY_TLS_RTT_VAL("Public(Commit)",
                     MLSMessage,
                     public_message_commit,
                     require_format(WireFormat::mls_plaintext));
  VERIFY_TLS_RTT_VAL("PrivateMessage",
                     MLSMessage,
                     private_message,
                     require_format(WireFormat::mls_ciphertext));

  return std::nullopt;
}

std::optional<std::string>
PassiveClientTestVector::verify()
{
  // Import everything
  signature_priv.set_public_key(cipher_suite);
  encryption_priv.set_public_key(cipher_suite);
  init_priv.set_public_key(cipher_suite);

  const auto& key_package_raw = var::get<KeyPackage>(key_package.message);
  const auto& welcome_raw = var::get<Welcome>(welcome.message);

  auto ext_psks = std::map<bytes, bytes>{};
  for (const auto& [id, psk] : external_psks) {
    ext_psks.insert_or_assign(id, psk);
  }

  // Join the group and follow along
  auto state = State(init_priv,
                     encryption_priv,
                     signature_priv,
                     key_package_raw,
                     welcome_raw,
                     ratchet_tree,
                     ext_psks);
  VERIFY_EQUAL(
    "initial epoch", state.epoch_authenticator(), initial_epoch_authenticator);

  for (const auto& tve : epochs) {
    for (const auto& proposal : tve.proposals) {
      state.handle(proposal);
    }

    state = opt::get(state.handle(tve.commit));
    VERIFY_EQUAL(
      "epoch auth", state.epoch_authenticator(), tve.epoch_authenticator)
  }

  return std::nullopt;
}

} // namespace mls_vectors
