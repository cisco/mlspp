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
      return std::get<KeyPackage>(*this).init_key;

    case NodeType::parent:
      return std::get<ParentNode>(*this).public_key;
  }
}

///
/// OptionalNode
///

struct LeafNodeHashInput
{
  LeafIndex leaf_index;
  tls::optional<KeyPackage> key_package;

  TLS_SERIALIZABLE(leaf_index, key_package);
};

void
OptionalNode::set_leaf_hash(CipherSuite suite, LeafIndex index)
{
  auto hash_input_str = LeafNodeHashInput{};
  hash_input_str.leaf_index = index;
  if (has_value()) {
    hash_input_str.key_package = std::get<KeyPackage>(value());
  }

  auto hash_input = tls::marshal(hash_input_str);
  hash = Digest(suite).write(hash_input).digest();
}

struct ParentNodeHashInput
{
  NodeIndex node_index;
  tls::optional<ParentNode> parent_node;
  tls::opaque<1> left_hash;
  tls::opaque<1> right_hash;

  TLS_SERIALIZABLE(node_index, parent_node, left_hash, right_hash);
};

void
OptionalNode::set_parent_hash(CipherSuite suite,
                              NodeIndex index,
                              const bytes& left,
                              const bytes& right)
{
  auto hash_input_str = ParentNodeHashInput{};
  hash_input_str.node_index = index;
  hash_input_str.left_hash = left;
  hash_input_str.right_hash = right;
  if (has_value()) {
    hash_input_str.parent_node = std::get<ParentNode>(value());
  }

  auto hash_input = tls::marshal(hash_input_str);
  hash = Digest(suite).write(hash_input).digest();
}

} // namespace mls
