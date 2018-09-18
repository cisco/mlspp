#pragma once

#include "crypto.h"
#include "messages.h"
#include "ratchet_tree.h"
#include "roster.h"
#include <vector>

namespace mls {

class State
{
public:
  ///
  /// Constructors
  ///

  // Default constructor does not have a useful semantic.  It should
  // only be used for constructing blank states, e.g., for unmarshal
  State() = default;

  // Initialize an empty group
  State(const bytes& group_id, const SignaturePrivateKey& identity_priv);

  // Initialize a group from a Add (for group-initiated join)
  State(const SignaturePrivateKey& identity_priv,
        const bytes& init_secret,
        const Welcome& welcome,
        const Handshake& handshake);

  ///
  /// Message factories
  ///

  // Generate a Add message (for group-initiated join)
  std::pair<Welcome, Handshake> add(const UserInitKey& user_init_key) const;

  // Generate an Update message (for post-compromise security)
  Handshake update(const bytes& leaf_secret);

  // Generate a Remove message (to remove another participant)
  Handshake remove(uint32_t index) const;

  ///
  /// Generic handshake message handler
  ///

  // Handle a Handshake message
  State handle(const Handshake& handshake) const;

  ///
  /// Specific operation handlers
  ///
  /// XXX(rlb@ipv.sx) These can probably be private
  ///

  // Handle a Add (for existing participants only)
  void handle(const Add& add);

  // Handle an Update (for the participant that sent the update)
  void handle(uint32_t index, const Update& update);

  // Handle a Remove (for the remaining participants, obviously)
  void handle(uint32_t index, const Remove& remove);

  epoch_t epoch() const { return _epoch; }
  uint32_t index() const { return _index; }

private:
  // Shared confirmed state:
  //
  // struct {
  //   opaque group_id<0..255>;
  //   uint32 epoch;
  //   Credential roster<1..2^24-1>;
  //   PublicKey tree<1..2^24-1>;
  //   GroupOperation transcript<0..2^24-1>;
  // } GroupState;
  tls::opaque<2> _group_id;
  epoch_t _epoch;
  Roster _roster;
  RatchetTree _tree;
  tls::vector<GroupOperation, 3> _transcript;

  // Shared secret state
  tls::opaque<1> _message_master_secret;
  tls::opaque<1> _init_secret;
  DHPrivateKey _add_priv;

  // Per-participant state
  uint32_t _index;
  SignaturePrivateKey _identity_priv;
  bytes _cached_leaf_secret;

  // Compare the **shared** attributes of the states
  friend bool operator==(const State& lhs, const State& rhs);
  friend bool operator!=(const State& lhs, const State& rhs);

  // Inner logic shared by Update, self-Update, and Remove handlers
  template<typename Message>
  void update_leaf(uint32_t index,
                   const RatchetPath& path,
                   const Message& message,
                   const optional<bytes>& leaf_secret);

  // Derive the secrets for an epoch, given some new entropy
  void derive_epoch_keys(bool add,
                         const bytes& update_secret,
                         const bytes& message);

  // Sign this state with the associated private key
  Handshake sign(const GroupOperation& operation) const;

  // Verify this state with the indicated public key
  bool verify(uint32_t signer_index, const bytes& signature) const;
};

} // namespace mls
