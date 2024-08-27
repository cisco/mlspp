#pragma once

#include <mls/messages.h>
#include <mls/treekem.h>
#include <vector>

namespace mls_ds {

namespace mls = MLS_NAMESPACE;

class TreeFollower
{
public:
  // Construct a one-member tree
  TreeFollower(mls::KeyPackage key_package);

  // Import a tree as a starting point for future updates
  TreeFollower(mls::TreeKEMPublicKey tree);

  // Update the tree with a set of proposals applied by a commit
  void update(const mls::MLSMessage& commit_message,
              const std::vector<mls::MLSMessage>& extra_proposals);

  // Accessors
  mls::CipherSuite cipher_suite() const { return _suite; }
  const mls::TreeKEMPublicKey& tree() const { return _tree; }

private:
  mls::CipherSuite _suite;
  mls::TreeKEMPublicKey _tree;
};

} // namespace mls_ds
