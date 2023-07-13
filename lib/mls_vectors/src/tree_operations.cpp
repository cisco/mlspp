#include <mls_vectors/mls_vectors.h>

#include "common.h"
#include "tree.h"

namespace mls_vectors {

using namespace mls;

const std::vector<TreeOperationsTestVector::Scenario>
  TreeOperationsTestVector::all_scenarios{
    Scenario::add_right_edge,    Scenario::add_internal,    Scenario::update,
    Scenario::remove_right_edge, Scenario::remove_internal,
  };

TreeOperationsTestVector::TreeOperationsTestVector(mls::CipherSuite suite,
                                                   Scenario scenario)
  : PseudoRandom(suite, "tree-operations")
  , proposal_sender(0)
{
  auto init_priv = prg.hpke_key("init_key");
  auto enc_priv = prg.hpke_key("encryption_key");
  auto sig_priv = prg.signature_key("signature_key");
  auto identity = prg.secret("identity");
  auto credential = Credential::basic(identity);
  auto key_package = KeyPackage{
    suite,
    init_priv.public_key,
    { suite,
      enc_priv.public_key,
      sig_priv.public_key,
      credential,
      Capabilities::create_default(),
      Lifetime::create_default(),
      {},
      sig_priv },
    {},
    sig_priv,
  };

  switch (scenario) {
    case Scenario::add_right_edge: {
      auto tc = TreeTestCase::full(suite, prg, LeafCount{ 8 }, "tc");

      proposal = Proposal{ Add{ key_package } };

      tree_before = tc.pub;

      tree_after = tree_before;
      tree_after.add_leaf(key_package.leaf_node);
      break;
    }

    case Scenario::add_internal: {
      auto tc = TreeTestCase::full(suite, prg, LeafCount{ 8 }, "tc");

      proposal = Proposal{ Add{ key_package } };

      tree_before = tc.pub;
      tree_before.blank_path(LeafIndex{ 4 });

      tree_after = tree_before;
      tree_after.add_leaf(key_package.leaf_node);
      break;
    }

    case Scenario::update: {
      auto tc = TreeTestCase::full(suite, prg, LeafCount{ 8 }, "tc");

      proposal_sender = LeafIndex{ 3 };
      proposal = Proposal{ Update{ key_package.leaf_node } };

      tree_before = tc.pub;

      tree_after = tree_before;
      tree_after.update_leaf(proposal_sender, key_package.leaf_node);
      break;
    }

    case Scenario::remove_right_edge: {
      auto tc = TreeTestCase::full(suite, prg, LeafCount{ 9 }, "tc");

      auto removed = LeafIndex{ 8 };
      proposal = Proposal{ Remove{ removed } };

      tree_before = tc.pub;

      tree_after = tree_before;
      tree_after.blank_path(removed);
      tree_after.truncate();
      break;
    }

    case Scenario::remove_internal: {
      auto tc = TreeTestCase::full(suite, prg, LeafCount{ 8 }, "tc");

      auto removed = LeafIndex{ 4 };
      proposal = Proposal{ Remove{ removed } };

      tree_before = tc.pub;

      tree_after = tree_before;
      tree_after.blank_path(removed);
      tree_after.truncate();
      break;
    }
  }
}

std::optional<std::string>
TreeOperationsTestVector::verify() const
{
  auto tree = tree_before;
  auto apply = overloaded{
    [&](const Add& add) { tree.add_leaf(add.key_package.leaf_node); },

    [&](const Update& update) {
      tree.update_leaf(proposal_sender, update.leaf_node);
    },

    [&](const Remove& remove) {
      tree.blank_path(remove.removed);
      tree.truncate();
    },

    [](const auto& /* other */) {
      throw InvalidParameterError("invalid proposal type");
    },
  };

  var::visit(apply, proposal.content);
  VERIFY_EQUAL("tree after", tree, tree_after);

  return std::nullopt;
}

} // namespace mls_vectors
