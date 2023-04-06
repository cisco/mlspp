#include "mls_client_impl.h"
#include "json_details.h"
#include <bytes/bytes.h>

using grpc::StatusCode;
using nlohmann::json;
using namespace bytes_ns;

static inline std::string
bytes_to_string(const std::vector<uint8_t>& data)
{
  return { data.begin(), data.end() };
}

static inline std::vector<uint8_t>
string_to_bytes(const std::string& str)
{
  return { str.begin(), str.end() };
}

static inline std::string
marshal_message(mls::MLSMessage&& msg)
{
  return bytes_to_string(tls::marshal(msg));
}

template<typename T>
T
unmarshal_message(const std::string& str)
{
  auto data = string_to_bytes(str);
  auto msg = tls::get<mls::MLSMessage>(data);
  return var::get<T>(msg.message);
}

static inline mls::CipherSuite
mls_suite(uint32_t suite_id)
{
  return static_cast<mls::CipherSuite::ID>(suite_id);
}

// Map C++ exceptions to gRPC errors
static inline Status
catch_wrap(std::function<Status()>&& f)
{
  try {
    return f();
  } catch (const std::exception& e) {
    return Status(StatusCode::INTERNAL, e.what());
  }
}

template<typename Req, typename F>
Status
MLSClientImpl::state_wrap(const Req* req, F&& f)
{
  auto maybe_state = load_state(req->state_id());
  if (!maybe_state) {
    return Status(StatusCode::NOT_FOUND, "Unknown state");
  }

  try {
    return f(*maybe_state);
  } catch (const std::exception& e) {
    return Status(StatusCode::INTERNAL, e.what());
  }
}

// gRPC methods
Status
MLSClientImpl::Name(ServerContext* /* context */,
                    const NameRequest* /* request */,
                    NameResponse* reply)
{
  static constexpr char name[] = "mlspp";
  reply->set_name(name);
  return Status::OK;
}

Status
MLSClientImpl::SupportedCiphersuites(
  ServerContext* /* context */,
  const SupportedCiphersuitesRequest* /* request */,
  SupportedCiphersuitesResponse* reply)
{
  reply->clear_ciphersuites();
  for (const auto suite : mls::all_supported_suites) {
    reply->add_ciphersuites(static_cast<uint32_t>(suite));
  }
  return Status::OK;
}

// Ways to become a member of a group
Status
MLSClientImpl::CreateGroup(ServerContext* /* context */,
                           const CreateGroupRequest* request,
                           CreateGroupResponse* response)
{
  return catch_wrap([=]() { return create_group(request, response); });
}

Status
MLSClientImpl::CreateKeyPackage(ServerContext* /* context */,
                                const CreateKeyPackageRequest* request,
                                CreateKeyPackageResponse* response)
{
  return catch_wrap([=]() { return create_key_package(request, response); });
}

Status
MLSClientImpl::JoinGroup(ServerContext* /* context */,
                         const JoinGroupRequest* request,
                         JoinGroupResponse* response)
{
  return catch_wrap([=]() { return join_group(request, response); });
}

Status
MLSClientImpl::ExternalJoin(ServerContext* /* context */,
                            const ExternalJoinRequest* request,
                            ExternalJoinResponse* response)
{
  return catch_wrap([=]() { return external_join(request, response); });
}

// Access information from a group state
Status
MLSClientImpl::GroupInfo(ServerContext* /* context */,
                         const GroupInfoRequest* request,
                         GroupInfoResponse* response)
{
  return state_wrap(
    request, [=](auto& state) { return group_info(state, request, response); });
}

Status
MLSClientImpl::StateAuth(ServerContext* /* context */,
                         const StateAuthRequest* request,
                         StateAuthResponse* response)
{
  return state_wrap(
    request, [=](auto& state) { return state_auth(state, request, response); });
}

Status
MLSClientImpl::Export(ServerContext* /* context */,
                      const ExportRequest* request,
                      ExportResponse* response)
{
  return state_wrap(
    request, [=](auto& state) { return do_export(state, request, response); });
}

Status
MLSClientImpl::Protect(ServerContext* /* context */,
                       const ProtectRequest* request,
                       ProtectResponse* response)
{
  return state_wrap(
    request, [=](auto& state) { return protect(state, request, response); });
}

Status
MLSClientImpl::Unprotect(ServerContext* /* context */,
                         const UnprotectRequest* request,
                         UnprotectResponse* response)
{
  return state_wrap(
    request, [=](auto& state) { return unprotect(state, request, response); });
}

Status
MLSClientImpl::StorePSK(ServerContext* /* context */,
                        const StorePSKRequest* request,
                        StorePSKResponse* /* response */)
{
  auto id = request->state_or_transaction_id();
  auto psk_id = string_to_bytes(request->psk_id());
  auto psk_secret = string_to_bytes(request->psk_secret());

  auto* join = load_join(id);
  if (join) {
    join->external_psks.insert_or_assign(psk_id, psk_secret);
    return Status::OK;
  }

  auto* cached = load_state(id);
  if (!cached) {
    throw Status(StatusCode::NOT_FOUND, "Unknown state");
  }

  cached->state.add_external_psk(psk_id, psk_secret);
  return Status::OK;
}

// Operations using a group state
Status
MLSClientImpl::AddProposal(ServerContext* /* context */,
                           const AddProposalRequest* request,
                           ProposalResponse* response)
{
  return state_wrap(request, [=](auto& state) {
    return add_proposal(state, request, response);
  });
}

Status
MLSClientImpl::UpdateProposal(ServerContext* /* context */,
                              const UpdateProposalRequest* request,
                              ProposalResponse* response)
{
  return state_wrap(request, [=](auto& state) {
    return update_proposal(state, request, response);
  });
}

Status
MLSClientImpl::RemoveProposal(ServerContext* /* context */,
                              const RemoveProposalRequest* request,
                              ProposalResponse* response)
{
  return state_wrap(request, [=](auto& state) {
    return remove_proposal(state, request, response);
  });
}

Status
MLSClientImpl::ExternalPSKProposal(ServerContext* /* context */,
                                   const ExternalPSKProposalRequest* request,
                                   ProposalResponse* response)
{
  return state_wrap(request, [=](auto& state) {
    return external_psk_proposal(state, request, response);
  });
}

Status
MLSClientImpl::ResumptionPSKProposal(
  ServerContext* /* context */,
  const ResumptionPSKProposalRequest* request,
  ProposalResponse* response)
{
  return state_wrap(request, [=](auto& state) {
    return resumption_psk_proposal(state, request, response);
  });
}

Status
MLSClientImpl::GroupContextExtensionsProposal(
  ServerContext* /* context */,
  const GroupContextExtensionsProposalRequest* request,
  ProposalResponse* response)
{
  return state_wrap(request, [=](auto& state) {
    return group_context_extensions_proposal(state, request, response);
  });
}

Status
MLSClientImpl::Commit(ServerContext* /* context */,
                      const CommitRequest* request,
                      CommitResponse* response)
{
  return state_wrap(
    request, [=](auto& state) { return commit(state, request, response); });
}

Status
MLSClientImpl::HandleCommit(ServerContext* /* context */,
                            const HandleCommitRequest* request,
                            HandleCommitResponse* response)
{
  return state_wrap(request, [=](auto& state) {
    return handle_commit(state, request, response);
  });
}

Status
MLSClientImpl::HandlePendingCommit(ServerContext* /* context */,
                                   const HandlePendingCommitRequest* request,
                                   HandleCommitResponse* response)
{
  return state_wrap(request, [=](auto& state) {
    return handle_pending_commit(state, request, response);
  });
}

Status
MLSClientImpl::NewMemberAddProposal(ServerContext* /* context */,
                                    const NewMemberAddProposalRequest* request,
                                    NewMemberAddProposalResponse* response)
{
  return catch_wrap(
    [=]() { return new_member_add_proposal(request, response); });
}

Status
MLSClientImpl::CreateExternalSigner(ServerContext* /* context */,
                                    const CreateExternalSignerRequest* request,
                                    CreateExternalSignerResponse* response)
{
  return catch_wrap(
    [=]() { return create_external_signer(request, response); });
}

Status
MLSClientImpl::AddExternalSigner(ServerContext* /* context */,
                                 const AddExternalSignerRequest* request,
                                 ProposalResponse* response)
{
  return state_wrap(request, [=](auto& state) {
    return add_external_signer(state, request, response);
  });
}

Status
MLSClientImpl::ExternalSignerProposal(
  ServerContext* /* context */,
  const ExternalSignerProposalRequest* request,
  ProposalResponse* response)
{
  return catch_wrap(
    [=]() { return external_signer_proposal(request, response); });
}

Status
MLSClientImpl::ReInitProposal(ServerContext* /* context */,
                              const ReInitProposalRequest* request,
                              ProposalResponse* response)
{
  return state_wrap(request, [=](auto& state) {
    return reinit_proposal(state, request, response);
  });
}

Status
MLSClientImpl::ReInitCommit(ServerContext* /* context */,
                            const CommitRequest* request,
                            CommitResponse* response)
{
  return state_wrap(request, [=](auto& state) {
    return reinit_commit(state, request, response);
  });
}

Status
MLSClientImpl::HandlePendingReInitCommit(
  ServerContext* /* context */,
  const HandlePendingCommitRequest* request,
  HandleReInitCommitResponse* response)
{
  return state_wrap(request, [=](auto& state) {
    return handle_pending_reinit_commit(state, request, response);
  });
}

Status
MLSClientImpl::HandleReInitCommit(ServerContext* /* context */,
                                  const HandleCommitRequest* request,
                                  HandleReInitCommitResponse* response)
{
  return state_wrap(request, [=](auto& state) {
    return handle_reinit_commit(state, request, response);
  });
}

Status
MLSClientImpl::ReInitWelcome(ServerContext* /* context */,
                             const ReInitWelcomeRequest* request,
                             CreateSubgroupResponse* response)
{
  return catch_wrap([=]() { return reinit_welcome(request, response); });
}

Status
MLSClientImpl::HandleReInitWelcome(ServerContext* /* context */,
                                   const HandleReInitWelcomeRequest* request,
                                   JoinGroupResponse* response)
{
  return catch_wrap([=]() { return handle_reinit_welcome(request, response); });
}

// Factory for key packages
MLSClientImpl::KeyPackageWithSecrets
MLSClientImpl::new_key_package(mls::CipherSuite cipher_suite,
                               const bytes& identity)
{
  auto init_priv = mls::HPKEPrivateKey::generate(cipher_suite);
  auto encryption_priv = mls::HPKEPrivateKey::generate(cipher_suite);
  auto signature_priv = mls::SignaturePrivateKey::generate(cipher_suite);
  auto cred = mls::Credential::basic(identity);

  auto key_package = mls::KeyPackage(cipher_suite,
                                     init_priv.public_key,
                                     {
                                       cipher_suite,
                                       encryption_priv.public_key,
                                       signature_priv.public_key,
                                       cred,
                                       mls::Capabilities::create_default(),
                                       mls::Lifetime::create_default(),
                                       {},
                                       signature_priv,
                                     },
                                     {},
                                     signature_priv);
  return { init_priv, encryption_priv, signature_priv, key_package };
}

Status
MLSClientImpl::CreateBranch(ServerContext* /* context */,
                            const CreateBranchRequest* request,
                            CreateSubgroupResponse* response)
{
  return state_wrap(request, [=](auto& state) {
    return create_branch(state, request, response);
  });
}

Status
MLSClientImpl::HandleBranch(ServerContext* /* context */,
                            const HandleBranchRequest* request,
                            HandleBranchResponse* response)
{
  return state_wrap(request, [=](auto& state) {
    return handle_branch(state, request, response);
  });
}

Status
MLSClientImpl::Free(ServerContext* /* context */,
                    const FreeRequest* request,
                    FreeResponse* /* response */)
{
  const auto state_id = request->state_id();
  if (state_cache.count(state_id) == 0) {
    return Status(StatusCode::NOT_FOUND, "Unknown state");
  }

  remove_state(state_id);
  return Status::OK;
}

// Cached join transactions
uint32_t
MLSClientImpl::store_join(KeyPackageWithSecrets&& kp_priv)
{
  auto join_id = tls::get<uint32_t>(kp_priv.key_package.ref());
  auto entry = CachedJoin{ std::move(kp_priv), {} };
  join_cache.emplace(std::make_pair(join_id, std::move(entry)));
  return join_id;
}

MLSClientImpl::CachedJoin*
MLSClientImpl::load_join(uint32_t join_id)
{
  if (join_cache.count(join_id) == 0) {
    return nullptr;
  }
  return &join_cache.at(join_id);
}

// Cached group state
mls::MessageOpts
MLSClientImpl::CachedState::message_opts() const
{
  return { encrypt_handshake, {}, 0 };
}

void
MLSClientImpl::CachedState::reset_pending()
{
  pending_commit.reset();
  pending_state_id.reset();
}

std::string
MLSClientImpl::CachedState::marshal(const mls::MLSMessage& msg)
{
  return bytes_to_string(tls::marshal(msg));
}

mls::MLSMessage
MLSClientImpl::CachedState::unmarshal(const std::string& wire)
{
  return tls::get<mls::MLSMessage>(string_to_bytes(wire));
}

uint32_t
MLSClientImpl::store_state(mls::State&& state, bool encrypt_handshake)
{
  auto state_id = tls::get<uint32_t>(state.epoch_authenticator());
  state_id += state.index().val;

  auto entry = CachedState{ std::move(state), encrypt_handshake, {}, {} };
  state_cache.emplace(std::make_pair(state_id, std::move(entry)));
  return state_id;
}

MLSClientImpl::CachedState*
MLSClientImpl::load_state(uint32_t state_id)
{
  if (state_cache.count(state_id) == 0) {
    return nullptr;
  }
  return &state_cache.at(state_id);
}

uint32_t
MLSClientImpl::store_signer(mls::SignaturePrivateKey&& priv)
{
  auto signer_id = tls::get<uint32_t>(priv.public_key.data);
  auto entry = CachedSigner{ std::move(priv) };
  signer_cache.emplace(std::make_pair(signer_id, std::move(entry)));
  return signer_id;
}

MLSClientImpl::CachedSigner*
MLSClientImpl::load_signer(uint32_t signer_id)
{
  if (signer_cache.count(signer_id) == 0) {
    return nullptr;
  }
  return &signer_cache.at(signer_id);
}

MLSClientImpl::CachedState*
MLSClientImpl::find_state(const bytes& group_id, const mls::epoch_t epoch)
{
  auto entry = std::find_if(
    state_cache.begin(), state_cache.end(), [&](const auto& entry) {
      const auto& [id, cached] = entry;
      return cached.state.group_id() == group_id &&
             cached.state.epoch() == epoch;
    });

  if (entry == state_cache.end()) {
    return nullptr;
  }

  return &entry->second;
}

void
MLSClientImpl::remove_state(uint32_t state_id)
{
  state_cache.erase(state_id);
}

uint32_t
MLSClientImpl::store_reinit(KeyPackageWithSecrets&& kp_priv,
                            mls::State::Tombstone&& tombstone,
                            bool encrypt_handshake)
{
  auto reinit_id = tls::get<uint32_t>(kp_priv.key_package.ref());
  auto entry =
    CachedReInit{ std::move(kp_priv), std::move(tombstone), encrypt_handshake };
  reinit_cache.emplace(std::make_pair(reinit_id, std::move(entry)));
  return reinit_id;
}

MLSClientImpl::CachedReInit*
MLSClientImpl::load_reinit(uint32_t reinit_id)
{
  if (reinit_cache.count(reinit_id) == 0) {
    return nullptr;
  }
  return &reinit_cache.at(reinit_id);
}

void
MLSClientImpl::remove_reinit(uint32_t reinit_id)
{
  reinit_cache.erase(reinit_id);
}

Status
MLSClientImpl::group_context_extensions_proposal(
  CachedState& entry,
  const GroupContextExtensionsProposalRequest* request,
  ProposalResponse* response)
{
  auto ext_list = mls::ExtensionList{};
  for (int i = 0; i < request->extensions_size(); i++) {
    auto ext = request->extensions(i);
    auto ext_type = static_cast<mls::Extension::Type>(ext.extension_type());
    auto ext_data = string_to_bytes(ext.extension_data());
    ext_list.add(ext_type, ext_data);
  }

  auto message =
    entry.state.group_context_extensions(ext_list, entry.message_opts());

  response->set_proposal(entry.marshal(message));
  return Status::OK;
}

mls::LeafIndex
MLSClientImpl::find_member(const mls::TreeKEMPublicKey& tree,
                           const std::string& identity)
{
  const auto id = string_to_bytes(identity);
  auto index = mls::LeafIndex{ 0 };
  for (; index < tree.size; index.val++) {
    const auto maybe_leaf = tree.leaf_node(index);
    if (!maybe_leaf) {
      continue;
    }

    const auto& leaf = opt::get(maybe_leaf);
    const auto& basic = leaf.credential.get<mls::BasicCredential>();
    if (basic.identity == id) {
      break;
    }
  }

  if (!(index < tree.size)) {
    throw std::runtime_error("Unknown member identity");
  }

  return index;
}

mls::Proposal
MLSClientImpl::proposal_from_description(mls::CipherSuite suite,
                                         const bytes& group_id,
                                         const mls::TreeKEMPublicKey& tree,
                                         const ProposalDescription& desc)
{
  if (desc.proposal_type() == "add") {
    const auto kp_msg_data = string_to_bytes(desc.key_package());
    const auto kp_msg = tls::get<mls::MLSMessage>(kp_msg_data);
    const auto kp = var::get<mls::KeyPackage>(kp_msg.message);
    return { mls::Add{ kp } };
  }

  if (desc.proposal_type() == "remove") {
    const auto removed_index = find_member(tree, desc.removed_id());
    return { mls::Remove{ removed_index } };
  }

  if (desc.proposal_type() == "externalPSK") {
    const auto external_psk_id = string_to_bytes(desc.psk_id());
    const auto psk_id = mls::PreSharedKeyID{
      { mls::ExternalPSK{ external_psk_id } },
      mls::random_bytes(suite.secret_size()),
    };
    return { mls::PreSharedKey{ psk_id } };
  }

  if (desc.proposal_type() == "resumptionPSK") {
    const auto epoch = desc.epoch_id();
    const auto psk_id = mls::PreSharedKeyID{
      { mls::ResumptionPSK{
        mls::ResumptionPSKUsage::application, group_id, epoch } },
      mls::random_bytes(suite.secret_size()),
    };
    return { mls::PreSharedKey{ psk_id } };
  }

  auto ext_list = mls::ExtensionList{};
  for (int i = 0; i < desc.extensions_size(); i++) {
    auto ext = desc.extensions(i);
    auto ext_type = static_cast<mls::Extension::Type>(ext.extension_type());
    auto ext_data = string_to_bytes(ext.extension_data());
    ext_list.add(ext_type, ext_data);
  }

  if (desc.proposal_type() == "groupContextExtensions") {
    return { mls::GroupContextExtensions{ ext_list } };
  }

  if (desc.proposal_type() == "reinit") {
    return { mls::ReInit{
      string_to_bytes(desc.group_id()),
      mls::ProtocolVersion::mls10,
      static_cast<mls::CipherSuite::ID>(desc.cipher_suite()),
      ext_list } };
  }

  throw std::runtime_error("Unknown proposal-by-value type");
}

// Ways to join a group
Status
MLSClientImpl::create_group(const CreateGroupRequest* request,
                            CreateGroupResponse* response)
{
  auto group_id = string_to_bytes(request->group_id());
  auto cipher_suite = mls_suite(request->cipher_suite());
  auto identity = string_to_bytes(request->identity());

  auto leaf_priv = mls::HPKEPrivateKey::generate(cipher_suite);
  auto sig_priv = mls::SignaturePrivateKey::generate(cipher_suite);
  auto cred = mls::Credential::basic(identity);

  auto leaf_node = mls::LeafNode{
    cipher_suite,
    leaf_priv.public_key,
    sig_priv.public_key,
    cred,
    mls::Capabilities::create_default(),
    mls::Lifetime::create_default(),
    {},
    sig_priv,
  };

  auto state =
    mls::State(group_id, cipher_suite, leaf_priv, sig_priv, leaf_node, {});
  auto state_id = store_state(std::move(state), request->encrypt_handshake());

  response->set_state_id(state_id);
  return Status::OK;
}

Status
MLSClientImpl::create_key_package(const CreateKeyPackageRequest* request,
                                  CreateKeyPackageResponse* response)
{
  auto cipher_suite = mls_suite(request->cipher_suite());
  auto identity = string_to_bytes(request->identity());

  auto kp_priv = new_key_package(cipher_suite, identity);

  response->set_init_priv(bytes_to_string(kp_priv.init_priv.data));
  response->set_encryption_priv(bytes_to_string(kp_priv.encryption_priv.data));
  response->set_signature_priv(bytes_to_string(kp_priv.signature_priv.data));

  auto key_package = tls::marshal(mls::MLSMessage{ kp_priv.key_package });
  response->set_key_package(bytes_to_string(key_package));

  auto join_id = store_join(std::move(kp_priv));
  response->set_transaction_id(join_id);

  return Status::OK;
}

Status
MLSClientImpl::join_group(const JoinGroupRequest* request,
                          JoinGroupResponse* response)
{
  auto join = load_join(request->transaction_id());
  if (!join) {
    return Status(StatusCode::INVALID_ARGUMENT, "Unknown transaction ID");
  }

  auto welcome = unmarshal_message<mls::Welcome>(request->welcome());
  auto ratchet_tree = std::optional<mls::TreeKEMPublicKey>{};
  auto ratchet_tree_data = string_to_bytes(request->ratchet_tree());
  if (!ratchet_tree_data.empty()) {
    ratchet_tree = tls::get<mls::TreeKEMPublicKey>(ratchet_tree_data);
  }

  auto state = mls::State(join->kp_priv.init_priv,
                          std::move(join->kp_priv.encryption_priv),
                          std::move(join->kp_priv.signature_priv),
                          join->kp_priv.key_package,
                          welcome,
                          ratchet_tree,
                          join->external_psks);

  auto epoch_authenticator = state.epoch_authenticator();
  auto state_id = store_state(std::move(state), request->encrypt_handshake());

  response->set_state_id(state_id);
  response->set_epoch_authenticator(bytes_to_string(epoch_authenticator));
  return Status::OK;
}

Status
MLSClientImpl::external_join(const ExternalJoinRequest* request,
                             ExternalJoinResponse* response)
{
  const auto group_info_msg =
    unmarshal_message<mls::GroupInfo>(request->group_info());
  const auto suite = group_info_msg.group_context.cipher_suite;

  auto init_priv = mls::HPKEPrivateKey::generate(suite);
  auto leaf_priv = mls::HPKEPrivateKey::generate(suite);
  auto sig_priv = mls::SignaturePrivateKey::generate(suite);
  auto identity = string_to_bytes(request->identity());
  auto cred = mls::Credential::basic(identity);

  auto leaf = mls::LeafNode{
    suite,
    leaf_priv.public_key,
    sig_priv.public_key,
    cred,
    mls::Capabilities::create_default(),
    mls::Lifetime::create_default(),
    {},
    sig_priv,
  };

  auto kp = mls::KeyPackage(suite, init_priv.public_key, leaf, {}, sig_priv);

  // Import an external tree if present
  auto ratchet_tree = std::optional<mls::TreeKEMPublicKey>{};
  auto ratchet_tree_data = string_to_bytes(request->ratchet_tree());
  if (!ratchet_tree_data.empty()) {
    ratchet_tree = tls::get<mls::TreeKEMPublicKey>(ratchet_tree_data);
  }

  // If required, find our prior appearance and remove it
  auto remove_prior = std::optional<mls::LeafIndex>{};
  if (request->remove_prior()) {
    // Find the tree we're going to look at
    // XXX(RLB): This replicates logic in State::import_tree, but we need to
    // do it out here since this is where the knowledge of which leaf to
    // remove resides.
    auto tree = mls::TreeKEMPublicKey(suite);
    auto maybe_tree_extn =
      group_info_msg.extensions.find<mls::RatchetTreeExtension>();
    if (ratchet_tree) {
      tree = opt::get(ratchet_tree);
    } else if (maybe_tree_extn) {
      tree = opt::get(maybe_tree_extn).tree;
    } else {
      throw std::runtime_error("No tree available");
    }

    // Scan through to find a matching identity
    for (auto i = mls::LeafIndex{ 0 }; i < tree.size; i.val++) {
      const auto maybe_leaf = tree.leaf_node(i);
      if (!maybe_leaf) {
        continue;
      }

      const auto& leaf = opt::get(maybe_leaf);
      const auto& cred = leaf.credential.get<mls::BasicCredential>();
      if (cred.identity != identity) {
        continue;
      }

      remove_prior = i;
    }

    if (!remove_prior) {
      throw std::runtime_error("Prior appearance not found");
    }
  }

  // Install PSKs
  auto psks = std::map<bytes, bytes>{};
  for (int i = 0; i < request->psks_size(); i++) {
    const auto& psk = request->psks(i);
    const auto psk_id = string_to_bytes(psk.psk_id());
    const auto psk_secret = string_to_bytes(psk.psk_secret());
    psks.insert_or_assign(psk_id, psk_secret);
  }

  auto encrypt = request->encrypt_handshake();
  auto leaf_secret = mls::random_bytes(suite.secret_size());
  auto [commit, state] = mls::State::external_join(leaf_secret,
                                                   sig_priv,
                                                   kp,
                                                   group_info_msg,
                                                   ratchet_tree,
                                                   { {}, encrypt, 0 },
                                                   remove_prior,
                                                   psks);
  auto epoch_authenticator = state.epoch_authenticator();
  auto state_id = store_state(std::move(state), encrypt);

  response->set_state_id(state_id);
  response->set_commit(marshal_message(std::move(commit)));
  response->set_epoch_authenticator(bytes_to_string(epoch_authenticator));
  return Status::OK;
}

// Access information from a group state
Status
MLSClientImpl::group_info(CachedState& entry,
                          const GroupInfoRequest* request,
                          GroupInfoResponse* response)
{
  auto inline_tree = !request->external_tree();

  auto group_info = entry.state.group_info(inline_tree);

  response->set_group_info(marshal_message(group_info));
  if (!inline_tree) {
    auto ratchet_tree = bytes_to_string(tls::marshal(entry.state.tree()));
    response->set_ratchet_tree(ratchet_tree);
  }

  return Status::OK;
}

Status
MLSClientImpl::state_auth(CachedState& entry,
                          const StateAuthRequest* /* request */,
                          StateAuthResponse* response)
{
  auto secret = entry.state.epoch_authenticator();
  response->set_state_auth_secret(bytes_to_string(secret));
  return Status::OK;
}

Status
MLSClientImpl::do_export(CachedState& entry,
                         const ExportRequest* request,
                         ExportResponse* response)
{
  auto label = request->label();
  auto context = string_to_bytes(request->context());
  auto size = request->key_length();
  auto secret = entry.state.do_export(label, context, size);
  response->set_exported_secret(bytes_to_string(secret));
  return Status::OK;
}

Status
MLSClientImpl::protect(CachedState& entry,
                       const ProtectRequest* request,
                       ProtectResponse* response)
{
  auto aad = string_to_bytes(request->authenticated_data());
  auto pt = string_to_bytes(request->plaintext());
  auto ct = entry.state.protect(aad, pt, 0);
  response->set_ciphertext(marshal_message(std::move(ct)));
  return Status::OK;
}

Status
MLSClientImpl::unprotect(CachedState& entry,
                         const UnprotectRequest* request,
                         UnprotectResponse* response)
{
  auto ct_data = string_to_bytes(request->ciphertext());
  auto ct = tls::get<mls::MLSMessage>(ct_data);

  // Locate the right epoch to decrypt with
  const auto group_id = entry.state.group_id();
  const auto epoch = var::get<mls::PrivateMessage>(ct.message).get_epoch();

  auto* state = &entry.state;
  if (entry.state.epoch() != epoch) {
    auto prior_entry = find_state(group_id, epoch);
    if (!prior_entry) {
      throw std::runtime_error("Unknown state for unprotect");
    }

    state = &prior_entry->state;
  }

  // Decrypt the message
  auto [aad, pt] = state->unprotect(ct);

  response->set_authenticated_data(bytes_to_string(aad));
  response->set_plaintext(bytes_to_string(pt));
  return Status::OK;
}

// Operations on a running group
Status
MLSClientImpl::add_proposal(CachedState& entry,
                            const AddProposalRequest* request,
                            ProposalResponse* response)
{
  auto key_package = unmarshal_message<mls::KeyPackage>(request->key_package());
  auto message = entry.state.add(key_package, entry.message_opts());

  response->set_proposal(entry.marshal(message));
  return Status::OK;
}

Status
MLSClientImpl::update_proposal(CachedState& entry,
                               const UpdateProposalRequest* /* request */,
                               ProposalResponse* response)
{
  auto leaf_priv = mls::HPKEPrivateKey::generate(entry.state.cipher_suite());
  auto message = entry.state.update(leaf_priv, {}, entry.message_opts());

  response->set_proposal(entry.marshal(message));
  return Status::OK;
}

Status
MLSClientImpl::remove_proposal(CachedState& entry,
                               const RemoveProposalRequest* request,
                               ProposalResponse* response)
{
  auto removed_index = find_member(entry.state.tree(), request->removed_id());
  auto message = entry.state.remove(removed_index, entry.message_opts());

  response->set_proposal(entry.marshal(message));
  return Status::OK;
}

Status
MLSClientImpl::external_psk_proposal(CachedState& entry,
                                     const ExternalPSKProposalRequest* request,
                                     ProposalResponse* response)

{
  auto psk_id = string_to_bytes(request->psk_id());

  auto message = entry.state.pre_shared_key(psk_id, entry.message_opts());

  response->set_proposal(entry.marshal(message));
  return Status::OK;
}

Status
MLSClientImpl::resumption_psk_proposal(
  CachedState& entry,
  const ResumptionPSKProposalRequest* request,
  ProposalResponse* response)
{
  auto group_id = entry.state.group_id();
  auto epoch = request->epoch_id();

  auto message =
    entry.state.pre_shared_key(group_id, epoch, entry.message_opts());

  response->set_proposal(entry.marshal(message));
  return Status::OK;
}

Status
MLSClientImpl::commit(CachedState& entry,
                      const CommitRequest* request,
                      CommitResponse* response)
{
  // Unmarshal and handle external / by_reference proposals
  const auto by_reference_size = request->by_reference_size();
  for (int i = 0; i < by_reference_size; i++) {
    auto msg = entry.unmarshal(request->by_reference(i));
    auto should_be_null = entry.state.handle(msg);
    if (should_be_null) {
      throw std::runtime_error("Commit included among proposals");
    }
  }

  // Create by-value proposals
  auto by_value = std::vector<mls::Proposal>();
  for (int i = 0; i < request->by_value_size(); i++) {
    const auto desc = request->by_value(i);
    const auto proposal = proposal_from_description(entry.state.cipher_suite(),
                                                    entry.state.group_id(),
                                                    entry.state.tree(),
                                                    desc);
    by_value.emplace_back(std::move(proposal));
  }

  auto force_path = request->force_path();
  auto inline_tree = !request->external_tree();

  auto leaf_secret =
    mls::random_bytes(entry.state.cipher_suite().secret_size());
  auto [commit, welcome, next] =
    entry.state.commit(leaf_secret,
                       mls::CommitOpts{ by_value, inline_tree, force_path, {} },
                       entry.message_opts());

  if (!inline_tree) {
    auto ratchet_tree = bytes_to_string(tls::marshal(next.tree()));
    response->set_ratchet_tree(ratchet_tree);
  }

  auto next_id = store_state(std::move(next), entry.encrypt_handshake);

  auto commit_data = entry.marshal(commit);
  response->set_commit(commit_data);

  entry.pending_commit = commit_data;
  entry.pending_state_id = next_id;

  response->set_welcome(marshal_message(welcome));
  return Status::OK;
}

Status
MLSClientImpl::handle_commit(CachedState& entry,
                             const HandleCommitRequest* request,
                             HandleCommitResponse* response)
{
  // Handle our own commits with caching
  auto commit_data = request->commit();
  if (entry.pending_commit && commit_data == opt::get(entry.pending_commit)) {
    response->set_state_id(opt::get(entry.pending_state_id));
    entry.reset_pending();
    return Status::OK;
  } else if (entry.pending_state_id) {
    remove_state(opt::get(entry.pending_state_id));
    entry.reset_pending();
  }

  // Handle the provided proposals, then the commit
  const auto proposal_size = request->proposal_size();
  for (int i = 0; i < proposal_size; i++) {
    auto msg = entry.unmarshal(request->proposal(i));
    auto should_be_null = entry.state.handle(msg);
    if (should_be_null) {
      throw std::runtime_error("Commit included among proposals");
    }
  }

  auto commit = entry.unmarshal(request->commit());
  auto should_be_next = entry.state.handle(commit);
  if (!should_be_next) {
    throw std::runtime_error("Commit failed to produce a new state");
  }

  auto& next = opt::get(should_be_next);
  auto epoch_authenticator = next.epoch_authenticator();
  auto next_id = store_state(std::move(next), entry.encrypt_handshake);

  response->set_state_id(next_id);
  response->set_epoch_authenticator(bytes_to_string(epoch_authenticator));
  return Status::OK;
}

Status
MLSClientImpl::handle_pending_commit(
  CachedState& entry,
  const HandlePendingCommitRequest* /* request */,
  HandleCommitResponse* response)
{
  if (!entry.pending_commit || !entry.pending_state_id) {
    throw std::runtime_error("No pending commit to handle");
  }

  const auto& next_id = opt::get(entry.pending_state_id);

  const auto* next = load_state(next_id);
  if (!next) {
    throw std::runtime_error("Internal error: No state for next ID");
  }

  const auto epoch_authenticator = next->state.epoch_authenticator();

  response->set_state_id(next_id);
  response->set_epoch_authenticator(bytes_to_string(epoch_authenticator));
  return Status::OK;
}

Status
MLSClientImpl::new_member_add_proposal(
  const NewMemberAddProposalRequest* request,
  NewMemberAddProposalResponse* response)
{
  auto group_info_msg_data = string_to_bytes(request->group_info());
  auto group_info_msg = tls::get<mls::MLSMessage>(group_info_msg_data);
  auto group_info = var::get<mls::GroupInfo>(group_info_msg.message);

  auto cipher_suite = group_info.group_context.cipher_suite;
  auto group_id = group_info.group_context.group_id;
  auto epoch = group_info.group_context.epoch;

  auto identity = string_to_bytes(request->identity());

  auto kp_priv = new_key_package(cipher_suite, identity);

  response->set_init_priv(bytes_to_string(kp_priv.init_priv.data));
  response->set_encryption_priv(bytes_to_string(kp_priv.encryption_priv.data));
  response->set_signature_priv(bytes_to_string(kp_priv.signature_priv.data));

  auto proposal = mls::State::new_member_add(
    group_id, epoch, kp_priv.key_package, kp_priv.signature_priv);
  response->set_proposal(marshal_message(std::move(proposal)));

  auto join_id = store_join(std::move(kp_priv));
  response->set_transaction_id(join_id);

  return Status::OK;
}

Status
MLSClientImpl::create_external_signer(
  const CreateExternalSignerRequest* request,
  CreateExternalSignerResponse* response)
{
  const auto cipher_suite = mls_suite(request->cipher_suite());
  const auto identity = string_to_bytes(request->identity());

  auto signature_priv = mls::SignaturePrivateKey::generate(cipher_suite);
  const auto cred = mls::Credential::basic(identity);

  const auto external_sender =
    mls::ExternalSender{ signature_priv.public_key, cred };
  response->set_external_sender(bytes_to_string(tls::marshal(external_sender)));

  const auto signer_id = store_signer(std::move(signature_priv));
  response->set_signer_id(signer_id);

  return Status::OK;
}

Status
MLSClientImpl::add_external_signer(CachedState& entry,
                                   const AddExternalSignerRequest* request,
                                   ProposalResponse* response)
{
  auto external_sender_data = string_to_bytes(request->external_sender());
  auto external_sender = tls::get<mls::ExternalSender>(external_sender_data);

  auto ext_list = entry.state.extensions();
  auto ext_senders = mls::ExternalSendersExtension{};
  auto curr_ext_senders = ext_list.find<mls::ExternalSendersExtension>();
  if (curr_ext_senders) {
    ext_senders = opt::get(curr_ext_senders);
  }

  ext_senders.senders.push_back(external_sender);
  ext_list.add(ext_senders);
  auto proposal =
    entry.state.group_context_extensions(ext_list, entry.message_opts());
  response->set_proposal(marshal_message(std::move(proposal)));

  return Status::OK;
}

Status
MLSClientImpl::external_signer_proposal(
  const ExternalSignerProposalRequest* request,
  ProposalResponse* response)
{
  auto group_info_msg_data = string_to_bytes(request->group_info());
  auto group_info_msg = tls::get<mls::MLSMessage>(group_info_msg_data);
  auto group_info = var::get<mls::GroupInfo>(group_info_msg.message);

  auto cipher_suite = group_info.group_context.cipher_suite;
  auto group_id = group_info.group_context.group_id;
  auto epoch = group_info.group_context.epoch;

  auto ratchet_tree_data = string_to_bytes(request->ratchet_tree());
  auto ratchet_tree = tls::get<mls::TreeKEMPublicKey>(ratchet_tree_data);

  // Look up the signer
  auto* signer = load_signer(request->signer_id());
  if (!signer) {
    throw std::runtime_error("Unknown signer ID");
  }

  // Look up the signer index of this signer
  const auto maybe_ext_senders =
    group_info.group_context.extensions.find<mls::ExternalSendersExtension>();
  if (!maybe_ext_senders) {
    throw std::runtime_error("No external senders allowed");
  }

  const auto& ext_senders = opt::get(maybe_ext_senders).senders;
  const auto where = std::find_if(
    ext_senders.begin(), ext_senders.end(), [&](const auto& sender) {
      return sender.signature_key == signer->signature_priv.public_key;
    });
  if (where == ext_senders.end()) {
    throw std::runtime_error("Requested signer not allowed for this group");
  }

  const auto signer_index = static_cast<uint32_t>(where - ext_senders.begin());

  // Sign the proposal
  const auto proposal = proposal_from_description(
    cipher_suite, group_id, ratchet_tree, request->description());
  auto signed_proposal = mls::external_proposal(cipher_suite,
                                                group_id,
                                                epoch,
                                                proposal,
                                                signer_index,
                                                signer->signature_priv);
  response->set_proposal(marshal_message(std::move(signed_proposal)));

  return Status::OK;
}

Status
MLSClientImpl::reinit_proposal(CachedState& entry,
                               const ReInitProposalRequest* request,
                               ProposalResponse* response)
{
  auto group_id = string_to_bytes(request->group_id());
  auto version = mls::ProtocolVersion::mls10;
  auto cipher_suite = mls_suite(request->cipher_suite());

  auto ext_list = mls::ExtensionList{};
  for (int i = 0; i < request->extensions_size(); i++) {
    auto ext = request->extensions(i);
    auto ext_type = static_cast<mls::Extension::Type>(ext.extension_type());
    auto ext_data = string_to_bytes(ext.extension_data());
    ext_list.add(ext_type, ext_data);
  }

  auto message = entry.state.reinit(
    group_id, version, cipher_suite, ext_list, entry.message_opts());

  response->set_proposal(entry.marshal(message));
  return Status::OK;
}

Status
MLSClientImpl::reinit_commit(CachedState& entry,
                             const CommitRequest* request,
                             CommitResponse* response)
{
  const auto inline_tree = !request->external_tree();
  const auto force_path = request->force_path();

  // XXX(RLB): Right now, the ReInit proposal must be provided by reference
  if (request->by_reference_size() != 1) {
    throw std::runtime_error("Malformed ReInit CommitRequest");
  }
  const auto reinit_proposal = entry.unmarshal(request->by_reference(0));
  const auto should_be_null = entry.state.handle(reinit_proposal);
  if (should_be_null) {
    throw std::runtime_error("Commit included among proposals");
  }

  const auto leaf_secret =
    mls::random_bytes(entry.state.cipher_suite().secret_size());
  const auto commit_opts = mls::CommitOpts{ {}, inline_tree, force_path, {} };
  auto [tombstone, commit] =
    entry.state.reinit_commit(leaf_secret, commit_opts, entry.message_opts());

  // Cache the reinit
  const auto my_leaf =
    opt::get(entry.state.tree().leaf_node(entry.state.index()));
  const auto identity = my_leaf.credential.get<mls::BasicCredential>().identity;
  auto kp_priv = new_key_package(tombstone.reinit.cipher_suite, identity);

  const auto reinit_id = store_reinit(
    std::move(kp_priv), std::move(tombstone), entry.encrypt_handshake);

  const auto commit_data = entry.marshal(commit);
  response->set_commit(commit_data);

  entry.pending_commit = commit_data;
  entry.pending_state_id = reinit_id;

  return Status::OK;
}

Status
MLSClientImpl::handle_pending_reinit_commit(
  CachedState& entry,
  const HandlePendingCommitRequest* /* request */,
  HandleReInitCommitResponse* response)
{
  if (!entry.pending_commit || !entry.pending_state_id) {
    throw std::runtime_error("No pending commit to handle");
  }

  const auto& reinit_id = opt::get(entry.pending_state_id);

  const auto* reinit = load_reinit(reinit_id);
  if (!reinit) {
    throw std::runtime_error("Internal error: No state for next ID");
  }

  const auto key_package = entry.marshal(reinit->kp_priv.key_package);
  const auto epoch_authenticator = reinit->tombstone.epoch_authenticator;

  response->set_reinit_id(reinit_id);
  response->set_key_package(key_package);
  response->set_epoch_authenticator(bytes_to_string(epoch_authenticator));
  return Status::OK;
}

Status
MLSClientImpl::handle_reinit_commit(CachedState& entry,
                                    const HandleCommitRequest* request,
                                    HandleReInitCommitResponse* response)
{
  // XXX(RLB): Right now, the ReInit proposal must be provided by reference
  if (request->proposal_size() != 1) {
    throw std::runtime_error("Malformed ReInit CommitRequest");
  }
  const auto reinit_proposal = entry.unmarshal(request->proposal(0));
  const auto should_be_null = entry.state.handle(reinit_proposal);
  if (should_be_null) {
    throw std::runtime_error("Commit included among proposals");
  }

  const auto commit = entry.unmarshal(request->commit());
  auto tombstone = entry.state.handle_reinit_commit(commit);

  // Cache the reinit
  const auto my_leaf =
    opt::get(entry.state.tree().leaf_node(entry.state.index()));
  const auto identity = my_leaf.credential.get<mls::BasicCredential>().identity;
  auto kp_priv = new_key_package(tombstone.reinit.cipher_suite, identity);

  const auto key_package = entry.marshal(kp_priv.key_package);
  const auto epoch_authenticator =
    bytes_to_string(tombstone.epoch_authenticator);

  auto reinit_id = store_reinit(
    std::move(kp_priv), std::move(tombstone), entry.encrypt_handshake);

  response->set_reinit_id(reinit_id);
  response->set_key_package(key_package);
  response->set_epoch_authenticator(epoch_authenticator);
  return Status::OK;
}

Status
MLSClientImpl::reinit_welcome(const ReInitWelcomeRequest* request,
                              CreateSubgroupResponse* response)
{
  // Load the reinit
  const auto reinit = load_reinit(request->reinit_id());
  if (!reinit) {
    return Status(StatusCode::INVALID_ARGUMENT, "Unknown reinit ID");
  }

  // Import the KeyPackages
  auto key_packages = std::vector<mls::KeyPackage>{};
  for (int i = 0; i < request->key_package_size(); i++) {
    const auto key_package_msg_data = string_to_bytes(request->key_package(i));
    const auto key_package_msg =
      tls::get<mls::MLSMessage>(key_package_msg_data);
    key_packages.emplace_back(
      var::get<mls::KeyPackage>(key_package_msg.message));
  }

  // Create the Welcome
  const auto inline_tree = !request->external_tree();
  const auto force_path = request->force_path();
  const auto cipher_suite = reinit->tombstone.reinit.cipher_suite;
  const auto leaf_secret = mls::random_bytes(cipher_suite.secret_size());
  auto [state, welcome] =
    reinit->tombstone.create_welcome(reinit->kp_priv.encryption_priv,
                                     reinit->kp_priv.signature_priv,
                                     reinit->kp_priv.key_package.leaf_node,
                                     key_packages,
                                     leaf_secret,
                                     { {}, inline_tree, force_path, {} });

  const auto welcome_data = tls::marshal(mls::MLSMessage{ welcome });

  // Store the resulting state
  auto epoch_authenticator = state.epoch_authenticator();
  auto tree = state.tree();
  auto state_id = store_state(std::move(state), reinit->encrypt_handshake);

  response->set_state_id(state_id);
  response->set_welcome(bytes_to_string(welcome_data));
  response->set_epoch_authenticator(bytes_to_string(epoch_authenticator));
  if (!inline_tree) {
    response->set_ratchet_tree(bytes_to_string(tls::marshal(tree)));
  }

  return Status::OK;
}

Status
MLSClientImpl::handle_reinit_welcome(const HandleReInitWelcomeRequest* request,
                                     JoinGroupResponse* response)
{
  // Load the reinit
  const auto reinit = load_reinit(request->reinit_id());
  if (!reinit) {
    return Status(StatusCode::INVALID_ARGUMENT, "Unknown reinit ID");
  }

  // Process the welcome
  const auto welcome_msg_data = string_to_bytes(request->welcome());
  const auto welcome_msg = tls::get<mls::MLSMessage>(welcome_msg_data);
  const auto welcome = var::get<mls::Welcome>(welcome_msg.message);

  auto ratchet_tree = std::optional<mls::TreeKEMPublicKey>{};
  auto ratchet_tree_data = string_to_bytes(request->ratchet_tree());
  if (!ratchet_tree_data.empty()) {
    ratchet_tree = tls::get<mls::TreeKEMPublicKey>(ratchet_tree_data);
  }

  auto state = reinit->tombstone.handle_welcome(reinit->kp_priv.init_priv,
                                                reinit->kp_priv.encryption_priv,
                                                reinit->kp_priv.signature_priv,
                                                reinit->kp_priv.key_package,
                                                welcome,
                                                ratchet_tree);

  // Store the resulting state
  auto epoch_authenticator = state.epoch_authenticator();
  auto state_id = store_state(std::move(state), reinit->encrypt_handshake);

  response->set_state_id(state_id);
  response->set_epoch_authenticator(bytes_to_string(epoch_authenticator));
  return Status::OK;
}

Status
MLSClientImpl::create_branch(CachedState& entry,
                             const CreateBranchRequest* request,
                             CreateSubgroupResponse* response)
{
  // Import KeyPackages
  auto key_packages = std::vector<mls::KeyPackage>{};
  for (int i = 0; i < request->key_packages_size(); i++) {
    const auto kp_msg_data = string_to_bytes(request->key_packages(i));
    const auto kp_msg = tls::get<mls::MLSMessage>(kp_msg_data);
    key_packages.emplace_back(var::get<mls::KeyPackage>(kp_msg.message));
  }

  // Import extensions
  auto ext_list = mls::ExtensionList{};
  for (int i = 0; i < request->extensions_size(); i++) {
    const auto ext = request->extensions(i);
    const auto ext_type =
      static_cast<mls::Extension::Type>(ext.extension_type());
    const auto ext_data = string_to_bytes(ext.extension_data());
    ext_list.add(ext_type, ext_data);
  }

  // Create the branch
  const auto my_leaf =
    opt::get(entry.state.tree().leaf_node(entry.state.index()));
  const auto identity = my_leaf.credential.get<mls::BasicCredential>().identity;

  const auto inline_tree = !request->external_tree();
  const auto force_path = request->force_path();
  const auto group_id = string_to_bytes(request->group_id());
  const auto cipher_suite = entry.state.cipher_suite();
  const auto kp_priv = new_key_package(cipher_suite, identity);
  const auto leaf_secret = mls::random_bytes(cipher_suite.secret_size());
  auto [next, welcome] =
    entry.state.create_branch(group_id,
                              kp_priv.encryption_priv,
                              kp_priv.signature_priv,
                              kp_priv.key_package.leaf_node,
                              ext_list,
                              key_packages,
                              leaf_secret,
                              { {}, inline_tree, force_path, {} });

  const auto epoch_authenticator = next.epoch_authenticator();

  const auto next_id = store_state(std::move(next), entry.encrypt_handshake);

  response->set_state_id(next_id);
  response->set_welcome(marshal_message(welcome));
  response->set_epoch_authenticator(bytes_to_string(epoch_authenticator));

  if (!inline_tree) {
    auto ratchet_tree = bytes_to_string(tls::marshal(next.tree()));
    response->set_ratchet_tree(ratchet_tree);
  }

  return Status::OK;
}

Status
MLSClientImpl::handle_branch(CachedState& entry,
                             const HandleBranchRequest* request,
                             HandleBranchResponse* response)
{
  auto join = load_join(request->transaction_id());
  if (!join) {
    return Status(StatusCode::INVALID_ARGUMENT, "Unknown transaction ID");
  }

  auto welcome = unmarshal_message<mls::Welcome>(request->welcome());
  auto ratchet_tree = std::optional<mls::TreeKEMPublicKey>{};
  auto ratchet_tree_data = string_to_bytes(request->ratchet_tree());
  if (!ratchet_tree_data.empty()) {
    ratchet_tree = tls::get<mls::TreeKEMPublicKey>(ratchet_tree_data);
  }

  auto state = entry.state.handle_branch(join->kp_priv.init_priv,
                                         join->kp_priv.encryption_priv,
                                         join->kp_priv.signature_priv,
                                         join->kp_priv.key_package,
                                         welcome,
                                         ratchet_tree);

  auto epoch_authenticator = state.epoch_authenticator();
  auto state_id = store_state(std::move(state), entry.encrypt_handshake);

  response->set_state_id(state_id);
  response->set_epoch_authenticator(bytes_to_string(epoch_authenticator));
  return Status::OK;
}
