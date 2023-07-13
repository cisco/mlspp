#include "tree.h"
#include <mls_vectors/mls_vectors.h>

namespace mls_vectors {

using namespace mls;

std::array<TreeStructure, 14> all_tree_structures{
  TreeStructure::full_tree_2,
  TreeStructure::full_tree_3,
  TreeStructure::full_tree_4,
  TreeStructure::full_tree_5,
  TreeStructure::full_tree_6,
  TreeStructure::full_tree_7,
  TreeStructure::full_tree_8,
  TreeStructure::full_tree_32,
  TreeStructure::full_tree_33,
  TreeStructure::full_tree_34,
  TreeStructure::internal_blanks_no_skipping,
  TreeStructure::internal_blanks_with_skipping,
  TreeStructure::unmerged_leaves_no_skipping,
  TreeStructure::unmerged_leaves_with_skipping,
};

std::array<TreeStructure, 11> treekem_test_tree_structures{
  // All cases except the big ones
  TreeStructure::full_tree_2,
  TreeStructure::full_tree_3,
  TreeStructure::full_tree_4,
  TreeStructure::full_tree_5,
  TreeStructure::full_tree_6,
  TreeStructure::full_tree_7,
  TreeStructure::full_tree_8,
  TreeStructure::internal_blanks_no_skipping,
  TreeStructure::internal_blanks_with_skipping,
  TreeStructure::unmerged_leaves_no_skipping,
  TreeStructure::unmerged_leaves_with_skipping,
};

TreeTestCase::TreeTestCase(CipherSuite suite_in,
                           PseudoRandom::Generator&& prg_in)
  : suite(suite_in)
  , prg(prg_in)
  , group_id(prg.secret("group_id"))
  , pub(suite)
{
  auto [where, enc_priv, sig_priv] = add_leaf();
  auto tree_priv = TreeKEMPrivateKey::solo(suite, where, enc_priv);
  auto priv_state = PrivateState{ sig_priv, tree_priv, { LeafIndex{ 0 } } };
  privs.insert_or_assign(where, priv_state);
}

std::tuple<LeafIndex, HPKEPrivateKey, SignaturePrivateKey>
TreeTestCase::add_leaf()
{
  leaf_counter += 1;
  auto ix = to_hex(tls::marshal(leaf_counter));
  auto enc_priv = prg.hpke_key("encryption_key" + ix);
  auto sig_priv = prg.signature_key("signature_key" + ix);
  auto identity = prg.secret("identity" + ix);

  auto credential = Credential::basic(identity);
  auto leaf_node = LeafNode{ suite,
                             enc_priv.public_key,
                             sig_priv.public_key,
                             credential,
                             Capabilities::create_default(),
                             Lifetime::create_default(),
                             {},
                             sig_priv };
  auto where = pub.add_leaf(leaf_node);
  pub.set_hash_all();
  return { where, enc_priv, sig_priv };
}

void
TreeTestCase::commit(LeafIndex from,
                     const std::vector<LeafIndex>& remove,
                     bool add,
                     std::optional<bytes> maybe_context)
{
  // Remove members from the tree
  for (auto i : remove) {
    pub.blank_path(i);
    privs.erase(i);
  }
  pub.set_hash_all();

  auto joiner = std::vector<LeafIndex>{};
  auto maybe_enc_priv = std::optional<HPKEPrivateKey>{};
  auto maybe_sig_priv = std::optional<SignaturePrivateKey>{};
  if (add) {
    auto [where, enc_priv, sig_priv] = add_leaf();
    joiner.push_back(where);
    maybe_enc_priv = enc_priv;
    maybe_sig_priv = sig_priv;
  }

  auto path_secret = std::optional<bytes>{};
  if (maybe_context) {
    // Create an UpdatePath
    path_counter += 1;
    auto ix = to_hex(tls::marshal(path_counter));
    auto leaf_secret = prg.secret("leaf_secret" + ix);
    auto priv = privs.at(from);

    auto context = opt::get(maybe_context);
    auto pub_before = pub;
    auto sender_priv =
      pub.update(from, leaf_secret, group_id, priv.sig_priv, {});
    auto path = pub.encap(sender_priv, context, joiner);

    // Process the UpdatePath at all the members
    for (auto& [leaf, priv_state] : privs) {
      if (leaf == from) {
        priv_state = PrivateState{ priv_state.sig_priv, sender_priv, { from } };
        continue;
      }

      priv_state.priv.decap(from, pub_before, context, path, joiner);
      priv_state.senders.push_back(from);
    }

    // Look up the path secret for the joiner
    if (!joiner.empty()) {
      auto index = joiner.front();
      auto [overlap, shared_path_secret, ok] =
        sender_priv.shared_path_secret(index);
      silence_unused(overlap);
      silence_unused(ok);

      path_secret = shared_path_secret;
    }
  }

  // Add a private entry for the joiner if we added someone
  if (!joiner.empty()) {
    auto index = joiner.front();
    auto ancestor = index.ancestor(from);
    auto enc_priv = opt::get(maybe_enc_priv);
    auto sig_priv = opt::get(maybe_sig_priv);
    auto tree_priv =
      TreeKEMPrivateKey::joiner(pub, index, enc_priv, ancestor, path_secret);
    privs.insert_or_assign(index,
                           PrivateState{ sig_priv, tree_priv, { from } });
  }
}

TreeTestCase
TreeTestCase::full(CipherSuite suite,
                   const PseudoRandom::Generator& prg,
                   LeafCount leaves,
                   const std::string& label)
{
  auto tc = TreeTestCase{ suite, prg.sub(label) };

  for (LeafIndex i{ 0 }; i.val < leaves.val - 1; i.val++) {
    tc.commit(i, {}, true, tc.prg.secret("context" + to_hex(tls::marshal(i))));
  }

  return tc;
}

TreeTestCase
TreeTestCase::with_structure(CipherSuite suite,
                             const PseudoRandom::Generator& prg,
                             TreeStructure tree_structure)
{
  switch (tree_structure) {
    case TreeStructure::full_tree_2:
      return full(suite, prg, LeafCount{ 2 }, "full_tree_2");

    case TreeStructure::full_tree_3:
      return full(suite, prg, LeafCount{ 3 }, "full_tree_3");

    case TreeStructure::full_tree_4:
      return full(suite, prg, LeafCount{ 4 }, "full_tree_4");

    case TreeStructure::full_tree_5:
      return full(suite, prg, LeafCount{ 5 }, "full_tree_5");

    case TreeStructure::full_tree_6:
      return full(suite, prg, LeafCount{ 6 }, "full_tree_6");

    case TreeStructure::full_tree_7:
      return full(suite, prg, LeafCount{ 7 }, "full_tree_7");

    case TreeStructure::full_tree_8:
      return full(suite, prg, LeafCount{ 8 }, "full_tree_8");

    case TreeStructure::full_tree_32:
      return full(suite, prg, LeafCount{ 32 }, "full_tree_32");

    case TreeStructure::full_tree_33:
      return full(suite, prg, LeafCount{ 33 }, "full_tree_33");

    case TreeStructure::full_tree_34:
      return full(suite, prg, LeafCount{ 34 }, "full_tree_34");

    case TreeStructure::internal_blanks_no_skipping: {
      auto tc = TreeTestCase::full(
        suite, prg, LeafCount{ 8 }, "internal_blanks_no_skipping");
      auto context = tc.prg.secret("context");
      tc.commit(
        LeafIndex{ 0 }, { LeafIndex{ 2 }, LeafIndex{ 3 } }, true, context);
      return tc;
    }

    case TreeStructure::internal_blanks_with_skipping: {
      auto tc = TreeTestCase::full(
        suite, prg, LeafCount{ 8 }, "internal_blanks_with_skipping");
      auto context = tc.prg.secret("context");
      tc.commit(LeafIndex{ 0 },
                { LeafIndex{ 1 }, LeafIndex{ 2 }, LeafIndex{ 3 } },
                false,
                context);
      return tc;
    }

    case TreeStructure::unmerged_leaves_no_skipping: {
      auto tc = TreeTestCase::full(
        suite, prg, LeafCount{ 7 }, "unmerged_leaves_no_skipping");
      auto context = tc.prg.secret("context");
      tc.commit(LeafIndex{ 0 }, {}, true, std::nullopt);
      return tc;
    }

    case TreeStructure::unmerged_leaves_with_skipping: {
      auto tc = TreeTestCase::full(
        suite, prg, LeafCount{ 1 }, "unmerged_leaves_with_skipping");

      // 0 adds 1..6
      tc.commit(LeafIndex{ 0 }, {}, true, std::nullopt);
      tc.commit(LeafIndex{ 0 }, {}, true, std::nullopt);
      tc.commit(LeafIndex{ 0 }, {}, true, std::nullopt);
      tc.commit(LeafIndex{ 0 }, {}, true, std::nullopt);
      tc.commit(LeafIndex{ 0 }, {}, true, std::nullopt);
      tc.commit(LeafIndex{ 0 }, {}, true, std::nullopt);

      // 0 reemoves 5
      tc.commit(LeafIndex{ 0 },
                { LeafIndex{ 5 } },
                false,
                tc.prg.secret("context_remove5"));

      // 4 commits without any proupposals
      tc.commit(LeafIndex{ 4 }, {}, false, tc.prg.secret("context_update4"));

      // 0 adds a new member
      tc.commit(LeafIndex{ 0 }, {}, true, std::nullopt);

      return tc;
    }

    default:
      throw InvalidParameterError("Unsupported tree structure");
  }
}

} // namespace mls_vectors
