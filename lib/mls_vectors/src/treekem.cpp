#include <mls_vectors/mls_vectors.h>

#include "common.h"
#include "tree.h"

namespace mls_vectors {

using namespace mls;

TreeKEMTestVector::TreeKEMTestVector(mls::CipherSuite suite,
                                     TreeStructure tree_structure)
  : PseudoRandom(suite, "treekem")
  , cipher_suite(suite)
{
  auto tc = TreeTestCase::with_structure(cipher_suite, prg, tree_structure);

  group_id = tc.group_id;
  epoch = prg.uint64("epoch");
  confirmed_transcript_hash = prg.secret("confirmed_transcript_hash");

  ratchet_tree = tc.pub;

  // Serialize out the private states
  for (LeafIndex index{ 0 }; index < ratchet_tree.size; index.val++) {
    if (tc.privs.count(index) == 0) {
      continue;
    }

    auto priv_state = tc.privs.at(index);
    auto enc_priv = priv_state.priv.private_key_cache.at(NodeIndex(index));
    auto path_secrets = std::vector<PathSecret>{};
    for (const auto& [node, path_secret] : priv_state.priv.path_secrets) {
      if (node == NodeIndex(index)) {
        // No need to serialize a secret for the leaf node
        continue;
      }

      path_secrets.push_back(PathSecret{ node, path_secret });
    }

    leaves_private.push_back(LeafPrivateInfo{
      index,
      enc_priv,
      priv_state.sig_priv,
      path_secrets,
    });
  }

  // Create test update paths
  for (LeafIndex sender{ 0 }; sender < ratchet_tree.size; sender.val++) {
    if (!tc.pub.has_leaf(sender)) {
      continue;
    }

    auto leaf_secret = prg.secret("update_path" + to_hex(tls::marshal(sender)));
    const auto& sig_priv = tc.privs.at(sender).sig_priv;

    auto pub = tc.pub;
    auto new_sender_priv =
      pub.update(sender, leaf_secret, group_id, sig_priv, {});

    auto group_context = GroupContext{ cipher_suite,
                                       group_id,
                                       epoch,
                                       pub.root_hash(),
                                       confirmed_transcript_hash,
                                       {} };
    auto ctx = tls::marshal(group_context);

    auto path = pub.encap(new_sender_priv, ctx, {});

    auto path_secrets = std::vector<std::optional<bytes>>{};
    for (LeafIndex to{ 0 }; to < ratchet_tree.size; to.val++) {
      if (to == sender || !pub.has_leaf(to)) {
        path_secrets.emplace_back(std::nullopt);
        continue;
      }

      auto [overlap, path_secret, ok] = new_sender_priv.shared_path_secret(to);
      silence_unused(overlap);
      silence_unused(ok);

      path_secrets.emplace_back(path_secret);
    }

    update_paths.push_back(UpdatePathInfo{
      sender,
      path,
      path_secrets,
      new_sender_priv.update_secret,
      pub.root_hash(),
    });
  }
}

std::optional<std::string>
TreeKEMTestVector::verify()
{
  // Finish initializing the ratchet tree
  ratchet_tree.suite = cipher_suite;
  ratchet_tree.set_hash_all();

  // Validate public state
  VERIFY("parent hash valid", ratchet_tree.parent_hash_valid());

  for (LeafIndex i{ 0 }; i < ratchet_tree.size; i.val++) {
    auto maybe_leaf = ratchet_tree.leaf_node(i);
    if (!maybe_leaf) {
      continue;
    }

    auto leaf = opt::get(maybe_leaf);
    VERIFY("leaf sig", leaf.verify(cipher_suite, { { group_id, i } }));
  }

  // Import private keys
  std::map<LeafIndex, TreeKEMPrivateKey> tree_privs;
  std::map<LeafIndex, SignaturePrivateKey> sig_privs;
  for (const auto& info : leaves_private) {
    auto enc_priv = info.encryption_priv;
    auto sig_priv = info.signature_priv;
    enc_priv.set_public_key(cipher_suite);
    sig_priv.set_public_key(cipher_suite);

    auto priv = TreeKEMPrivateKey{};
    priv.suite = cipher_suite;
    priv.index = info.index;
    priv.private_key_cache.insert_or_assign(NodeIndex(info.index), enc_priv);

    for (const auto& entry : info.path_secrets) {
      priv.path_secrets.insert_or_assign(entry.node, entry.path_secret);
    }

    VERIFY("priv consistent", priv.consistent(ratchet_tree));

    tree_privs.insert_or_assign(info.index, priv);
    sig_privs.insert_or_assign(info.index, sig_priv);
  }

  for (const auto& info : update_paths) {
    // Test decap of the existing group secrets
    const auto& from = info.sender;
    const auto& path = info.update_path;
    VERIFY("path parent hash valid",
           ratchet_tree.parent_hash_valid(from, path));

    auto ratchet_tree_after = ratchet_tree;
    ratchet_tree_after.merge(from, path);
    ratchet_tree_after.set_hash_all();
    VERIFY_EQUAL(
      "tree hash after", ratchet_tree_after.root_hash(), info.tree_hash_after);

    auto group_context = GroupContext{ cipher_suite,
                                       group_id,
                                       epoch,
                                       ratchet_tree_after.root_hash(),
                                       confirmed_transcript_hash,
                                       {} };
    auto ctx = tls::marshal(group_context);

    for (LeafIndex to{ 0 }; to < ratchet_tree_after.size; to.val++) {
      if (to == from || !ratchet_tree_after.has_leaf(to)) {
        continue;
      }

      auto priv = tree_privs.at(to);
      priv.decap(from, ratchet_tree_after, ctx, path, {});
      VERIFY_EQUAL("commit secret", priv.update_secret, info.commit_secret);

      auto [overlap, path_secret, ok] = priv.shared_path_secret(from);
      silence_unused(overlap);
      silence_unused(ok);
      VERIFY_EQUAL("path secret", path_secret, info.path_secrets[to.val]);
    }

    // Test encap/decap
    auto ratchet_tree_encap = ratchet_tree;
    auto leaf_secret = random_bytes(cipher_suite.secret_size());
    const auto& sig_priv = sig_privs.at(from);
    auto new_sender_priv =
      ratchet_tree_encap.update(from, leaf_secret, group_id, sig_priv, {});
    auto new_path = ratchet_tree_encap.encap(new_sender_priv, ctx, {});
    VERIFY("new path parent hash valid",
           ratchet_tree.parent_hash_valid(from, path));

    for (LeafIndex to{ 0 }; to < ratchet_tree_encap.size; to.val++) {
      if (to == from || !ratchet_tree_encap.has_leaf(to)) {
        continue;
      }

      auto priv = tree_privs.at(to);
      priv.decap(from, ratchet_tree_encap, ctx, new_path, {});
      VERIFY_EQUAL(
        "commit secret", priv.update_secret, new_sender_priv.update_secret);
    }
  }

  return std::nullopt;
}

} // namespace mls_vectors
