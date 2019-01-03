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

  // Initialize an empty group
  State(const bytes& group_id,
        CipherSuite suite,
        const SignaturePrivateKey& identity_priv);

  // Initialize a group from a Add (for group-initiated join)
  State(const SignaturePrivateKey& identity_priv,
        const bytes& init_secret,
        const Welcome& welcome,
        const Handshake& handshake);

  // Negotiate an initial state with another peer based on their
  // UserInitKey
  typedef std::pair<State, std::pair<Welcome, Handshake>> InitialInfo;
  static InitialInfo negotiate(
    const bytes& group_id,
    const std::vector<CipherSuite> supported_ciphersuites,
    const SignaturePrivateKey& identity_priv,
    const UserInitKey& user_init_key);

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
  State handle(uint32_t signer_index, const GroupOperation& operation) const;

  // Handle a Add (for existing participants only)
  void handle(const Add& add);

  // Handle an Update (for the participant that sent the update)
  void handle(uint32_t index, const Update& update);

  // Handle a Remove (for the remaining participants, obviously)
  void handle(uint32_t index, const Remove& remove);

  epoch_t epoch() const { return _epoch; }
  uint32_t index() const { return _index; }
  CipherSuite cipher_suite() const { return _suite; }

private:
  // Shared confirmed state:
  tls::opaque<2> _group_id;
  CipherSuite _suite;
  epoch_t _epoch;
  Roster _roster;
  RatchetTree _tree;
  tls::vector<GroupOperation, 3> _transcript;

  // Shared secret state
  tls::opaque<1> _message_master_secret;
  tls::opaque<1> _init_secret;

  // Per-participant state
  uint32_t _index;
  SignaturePrivateKey _identity_priv;
  bytes _cached_leaf_secret;

  // A zero vector, for convenience
  bytes _zero;

  // Compare the **shared** attributes of the states
  friend bool operator==(const State& lhs, const State& rhs);
  friend bool operator!=(const State& lhs, const State& rhs);

  // Marshal the shared confirmed state
  friend tls::ostream& operator<<(tls::ostream& out, const State& rhs);

  // Inner logic shared by Update, self-Update, and Remove handlers
  void update_leaf(uint32_t index,
                   const DirectPath& path,
                   const optional<bytes>& leaf_secret);

  // Derive the secrets for an epoch, given some new entropy
  void derive_epoch_keys(const bytes& update_secret);

  // Sign this state with the associated private key
  Handshake sign(const GroupOperation& operation) const;

  // Verify this state with the indicated public key
  bool verify(uint32_t signer_index, const bytes& signature) const;

  // XXX
  friend bytes derive_secret(CipherSuite suite,
                             const bytes& secret,
                             const std::string& label,
                             const State& state,
                             size_t size);
};

} // namespace mls
