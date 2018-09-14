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

  // Initialize a group from a GroupAdd (for group-initiated join)
  State(const SignaturePrivateKey& identity_priv,
        const bytes& init_secret,
        const Handshake<GroupAdd>& group_add);

  ///
  /// Message factories
  ///

  // Generate a GroupAdd message (for group-initiated join)
  Handshake<GroupAdd> add(const UserInitKey& user_init_key) const;

  // Generate an Update message (for post-compromise security)
  Handshake<Update> update(const bytes& leaf_secret) const;

  // Generate a Remove message (to remove another participant)
  Handshake<Remove> remove(uint32_t index) const;

  ///
  /// Message handlers
  ///

  // XXX(rlb@ipv.sx) We might want for these to produce a new state,
  // rather than modifying the current one, given that we will
  // probably want to keep old states around.  That could also be
  // done a little more explicitly with a copy constructor.

  // Handle a GroupAdd (for existing participants only)
  State handle(const Handshake<GroupAdd>& group_add) const;

  // Handle an Update (for the participant that sent the update)
  State handle(const Handshake<Update>& update, const bytes& leaf_secret) const;

  // Handle an Update (for the other participants)
  State handle(const Handshake<Update>& update) const;

  // Handle a Remove (for the remaining participants, obviously)
  State handle(const Handshake<Remove>& remove) const;

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
  //   opaque transcript_hash<0..255>;
  // } GroupState;
  tls::opaque<2> _group_id;
  epoch_t _epoch;
  Roster _roster;
  RatchetTree _ratchet_tree;
  // TODO transcript_hash;

  // Shared secret state
  tls::opaque<1> _message_master_secret;
  tls::opaque<1> _init_secret;
  DHPrivateKey _add_priv;

  // Per-participant state
  uint32_t _index;
  SignaturePrivateKey _identity_priv;

  // Compare the **shared** attributes of the states
  friend bool operator==(const State& lhs, const State& rhs);
  friend bool operator!=(const State& lhs, const State& rhs);

  // Spawn a new state (with a fresh epoch) from this state
  State spawn(const epoch_t& epoch) const;

  // Inner logic shared by UserAdd and GroupAdd handlers
  template<typename Message>
  void add_inner(const SignaturePublicKey& identity_key,
                 const Handshake<Message>& message);

  // Inner logic shared by Update, self-Update, and Remove handlers
  template<typename Message>
  void update_leaf(uint32_t index,
                   const RatchetPath& path,
                   const Handshake<Message>& message,
                   const optional<bytes>& leaf_secret);

  // Derive the secrets for an epoch, given some new entropy
  void derive_epoch_keys(bool add,
                         const bytes& update_secret,
                         const bytes& message);

  // Create a signed Handshake message, given a payload
  template<typename T>
  Handshake<T> sign(const T& body) const;

  // Verify a signed Handshake message against the list of
  // participants for the current epoch
  template<typename T>
  bool verify_now(const Handshake<T>& message) const;
};

} // namespace mls
