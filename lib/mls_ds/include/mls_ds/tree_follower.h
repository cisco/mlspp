#pragma once

#include <mls/messages.h>
#include <mls/treekem.h>
#include <vector>

namespace MLS_NAMESPACE::mls_ds {

using namespace MLS_NAMESPACE;

class TreeFollower
{
public:
  // Construct a one-member tree
  TreeFollower(const KeyPackage& key_package);

  // Import a tree as a starting point for future updates
  TreeFollower(TreeKEMPublicKey tree);

  // Update the tree with a set of proposals applied by a commit
  void update(const MLSMessage& commit_message,
              const std::vector<MLSMessage>& extra_proposals);

  // Accessors
  CipherSuite cipher_suite() const { return _suite; }
  const TreeKEMPublicKey& tree() const { return _tree; }

private:
  CipherSuite _suite;
  TreeKEMPublicKey _tree;
};

} // namespace MLS_NAMESPACE::mls_ds
