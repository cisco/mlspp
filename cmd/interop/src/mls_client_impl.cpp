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

Status
MLSClientImpl::StorePSK(ServerContext* /* context */,
                        const StorePSKRequest* request,
                        StorePSKResponse* response)
{
  return catch_wrap([=]() { return store_psk(request, response); });
}

// Access information from a group state
Status
MLSClientImpl::PublicGroupState(ServerContext* /* context */,
                                const PublicGroupStateRequest* request,
                                PublicGroupStateResponse* response)
{
  return state_wrap(request, [=](auto& state) {
    return public_group_state(state, request, response);
  });
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
MLSClientImpl::PSKProposal(ServerContext* /* context */,
                           const PSKProposalRequest* request,
                           ProposalResponse* response)
{
  return state_wrap(request, [=](auto& state) {
    return psk_proposal(state, request, response);
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

// Cached join transactions
uint32_t
MLSClientImpl::store_join(mls::HPKEPrivateKey&& init_priv,
                          mls::HPKEPrivateKey&& leaf_priv,
                          mls::SignaturePrivateKey&& sig_priv,
                          mls::KeyPackage&& kp)
{
  auto ref = kp.ref();
  auto ref_data = bytes(ref.size());
  std::copy(ref.begin(), ref.end(), ref_data.begin());

  auto join_id = tls::get<uint32_t>(ref_data);
  auto entry = CachedJoin{ std::move(init_priv),
                           std::move(leaf_priv),
                           std::move(sig_priv),
                           std::move(kp),
                           {} };
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

void
MLSClientImpl::remove_state(uint32_t state_id)
{
  state_cache.erase(state_id);
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

  auto init_priv = mls::HPKEPrivateKey::generate(cipher_suite);
  auto encryption_priv = mls::HPKEPrivateKey::generate(cipher_suite);
  auto signature_priv = mls::SignaturePrivateKey::generate(cipher_suite);
  auto cred = mls::Credential::basic(identity);

  response->set_init_priv(bytes_to_string(init_priv.data));
  response->set_encryption_priv(bytes_to_string(encryption_priv.data));
  response->set_signature_priv(bytes_to_string(signature_priv.data));

  auto leaf = mls::LeafNode{
    cipher_suite,
    encryption_priv.public_key,
    signature_priv.public_key,
    cred,
    mls::Capabilities::create_default(),
    mls::Lifetime::create_default(),
    {},
    signature_priv,
  };

  auto kp = mls::KeyPackage(
    cipher_suite, init_priv.public_key, leaf, {}, signature_priv);
  response->set_key_package(marshal_message(kp));

  auto join_id = store_join(std::move(init_priv),
                            std::move(encryption_priv),
                            std::move(signature_priv),
                            std::move(kp));
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

  auto state = mls::State(join->init_priv,
                          std::move(join->leaf_priv),
                          std::move(join->sig_priv),
                          join->key_package,
                          welcome,
                          ratchet_tree,
                          join->psks);
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
  const auto group_info =
    unmarshal_message<mls::GroupInfo>(request->public_group_state());
  const auto suite = group_info.group_context.cipher_suite;

  auto init_priv = mls::HPKEPrivateKey::generate(suite);
  auto leaf_priv = mls::HPKEPrivateKey::generate(suite);
  auto sig_priv = mls::SignaturePrivateKey::generate(suite);
  auto cred = mls::Credential::basic({});

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

  auto encrypt = request->encrypt_handshake();
  auto leaf_secret = mls::random_bytes(suite.secret_size());
  auto [commit, state] = mls::State::external_join(
    leaf_secret, sig_priv, kp, group_info, std::nullopt, { {}, encrypt, 0 });
  auto state_id = store_state(std::move(state), encrypt);

  response->set_state_id(state_id);
  response->set_commit(marshal_message(std::move(commit)));
  return Status::OK;
}

Status
MLSClientImpl::store_psk(const StorePSKRequest* request,
                         StorePSKResponse* /* response */)
{
  // Handle pre-join PSKs
  auto id = request->state_or_transaction_id();
  auto psk_id = string_to_bytes(request->psk_id());
  auto psk_secret = string_to_bytes(request->psk_secret());
  if (join_cache.count(id) > 0) {
    auto& cached = join_cache.at(id);
    cached.psks.insert_or_assign(psk_id, psk_secret);
  } else if (state_cache.count(id) > 0) {
    auto& cached = state_cache.at(id);
    cached.state.add_external_psk(psk_id, psk_secret);
  } else {
    throw std::runtime_error("Unknown state or transaction ID");
  }

  return Status::OK;
}

// Access information from a group state
Status
MLSClientImpl::public_group_state(CachedState& entry,
                                  const PublicGroupStateRequest* /* request */,
                                  PublicGroupStateResponse* response)
{
  auto group_info = entry.state.group_info();
  response->set_public_group_state(marshal_message(group_info));
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
  auto pt = string_to_bytes(request->application_data());
  auto ct = entry.state.protect({}, pt, 0);
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
  auto [aad, pt] = entry.state.unprotect(ct);
  mls::silence_unused(aad);

  // TODO(RLB) We should update the gRPC spec so that it returns the AAD as well
  // as the plaintext.
  response->set_application_data(bytes_to_string(pt));
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
  auto removed_id = string_to_bytes(request->removed_id());

  const auto& tree = entry.state.tree();
  auto removed_index = mls::LeafIndex{ 0 };
  for (; removed_index < tree.size; removed_index.val++) {
    const auto maybe_leaf = tree.leaf_node(removed_index);
    if (!maybe_leaf) {
      continue;
    }

    const auto& leaf = opt::get(maybe_leaf);
    const auto& basic = leaf.credential.get<mls::BasicCredential>();
    if (basic.identity == removed_id) {
      break;
    }
  }

  if (!(removed_index < tree.size)) {
    return Status(StatusCode::INVALID_ARGUMENT, "Unknown member identity");
  }

  auto message = entry.state.remove(removed_index, entry.message_opts());

  response->set_proposal(entry.marshal(message));
  return Status::OK;
}

Status
MLSClientImpl::psk_proposal(CachedState& entry,
                            const PSKProposalRequest* request,
                            ProposalResponse* response)
{
  auto psk_id = string_to_bytes(request->psk_id());

  auto message = entry.state.pre_shared_key(psk_id, entry.message_opts());

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

  auto force_path = request->force_path();
  auto inline_tree = !request->external_tree();
  auto inline_proposals = std::vector<mls::Proposal>();
#if 0
  // TODO(#265): Re-enable
  for (size_t i = 0; i < inline_proposals.size(); i++) {
    auto msg = entry.unmarshal(request->by_value(i));
    if (pt.sender.sender != entry.state.index().val) {
      return Status(grpc::INVALID_ARGUMENT,
                    "Inline proposal not from this member");
    }

    auto proposal = var::get_if<mls::Proposal>(&pt.content);
    if (!proposal) {
      return Status(grpc::INVALID_ARGUMENT, "Inline proposal not a proposal");
    }

    inline_proposals[i] = std::move(*proposal);
  }
#endif // 0

  auto leaf_secret =
    mls::random_bytes(entry.state.cipher_suite().secret_size());
  auto [commit, welcome, next] = entry.state.commit(
    leaf_secret,
    mls::CommitOpts{ inline_proposals, inline_tree, force_path, {} },
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
  const auto epoch_authenticator = next->state.epoch_authenticator();

  response->set_state_id(next_id);
  response->set_epoch_authenticator(bytes_to_string(epoch_authenticator));
  return Status::OK;
}
