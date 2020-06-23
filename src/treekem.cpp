#include "treekem.h"

namespace mls {

///
/// ParentNode
///

const NodeType ParentNode::type = NodeType::parent;

bool
operator==(const ParentNode& lhs, const ParentNode& rhs)
{
  return lhs.public_key == rhs.public_key &&
         lhs.unmerged_leaves == rhs.unmerged_leaves &&
         lhs.parent_hash == rhs.parent_hash;
}

///
/// Node
///

const HPKEPublicKey&
Node::public_key() const
{
  switch (inner_type()) {
    case NodeType::leaf:
      return std::get<ParentNode>(*this).public_key;

    case NodeType::parent:
      return std::get<ParentNode>(*this).public_key;
  }
}

///
/// OptionalNode
///

void
OptionalNode::set_leaf_hash(CipherSuite suite, LeafIndex index)
{
  // TODO
}

void
OptionalNode::set_parent_hash(CipherSuite suite,
                              NodeIndex index,
                              const bytes& left,
                              const bytes& right)
{
  // TODO
}

} // namespace mls
