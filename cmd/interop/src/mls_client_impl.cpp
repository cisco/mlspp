#include "mls_client_impl.h"
#include "json_details.h"

using grpc::StatusCode;
using nlohmann::json;

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

Status
MLSClientImpl::GenerateTestVector(ServerContext* /* context */,
                                  const GenerateTestVectorRequest* request,
                                  GenerateTestVectorResponse* reply)
{
  return catch_wrap([=]() { return generate_test_vector(request, reply); });
}

Status
MLSClientImpl::VerifyTestVector(ServerContext* /* context */,
                                const VerifyTestVectorRequest* request,
                                VerifyTestVectorResponse* /* reply */)
{
  return catch_wrap([=]() { return verify_test_vector(request); });
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
MLSClientImpl::HandleExternalCommit(ServerContext* /* context */,
                                    const HandleExternalCommitRequest* request,
                                    HandleExternalCommitResponse* response)
{
  return state_wrap(request, [=](auto& state) {
    return handle_external_commit(state, request, response);
  });
}

// Cached join transactions
uint32_t
MLSClientImpl::store_join(mls::HPKEPrivateKey&& init_priv,
                          mls::SignaturePrivateKey&& sig_priv,
                          mls::KeyPackage&& kp)
{
  auto join_id = tls::get<uint32_t>(kp.hash());
  auto entry =
    CachedJoin{ std::move(init_priv), std::move(sig_priv), std::move(kp) };
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
void
MLSClientImpl::CachedState::reset_pending()
{
  pending_commit.reset();
  pending_state_id.reset();
}

std::string
MLSClientImpl::CachedState::marshal(const mls::MLSPlaintext& pt)
{
  if (encrypt_handshake) {
    auto ct = state.encrypt(pt);
    return bytes_to_string(tls::marshal(ct));
  }

  return bytes_to_string(tls::marshal(pt));
}

mls::MLSPlaintext
MLSClientImpl::CachedState::unmarshal(const std::string& wire)
{
  if (encrypt_handshake) {
    auto ct = tls::get<mls::MLSCiphertext>(string_to_bytes(wire));
    return state.decrypt(ct);
  }

  return tls::get<mls::MLSPlaintext>(string_to_bytes(wire));
}

uint32_t
MLSClientImpl::store_state(mls::State&& state, bool encrypt_handshake)
{
  auto state_id = tls::get<uint32_t>(state.authentication_secret());
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

// Fallible method implementations, wrapped before being exposed to gRPC
Status
MLSClientImpl::verify_test_vector(const VerifyTestVectorRequest* request)
{
  auto error = std::optional<std::string>();
  auto tv_json = json::parse(request->test_vector());
  switch (request->test_vector_type()) {
    case TestVectorType::TREE_MATH: {
      error = tv_json.get<mls_vectors::TreeMathTestVector>().verify();
      break;
    }

    case TestVectorType::ENCRYPTION: {
      error = tv_json.get<mls_vectors::EncryptionTestVector>().verify();
      break;
    }

    case TestVectorType::KEY_SCHEDULE: {
      error = tv_json.get<mls_vectors::KeyScheduleTestVector>().verify();
      break;
    }

    case TestVectorType::TRANSCRIPT: {
      error = tv_json.get<mls_vectors::TranscriptTestVector>().verify();
      break;
    }

    case TestVectorType::TREEKEM: {
      auto tv = tv_json.get<mls_vectors::TreeKEMTestVector>();
      tv.initialize_trees();
      error = tv.verify();
      break;
    }

    case TestVectorType::MESSAGES: {
      error = tv_json.get<mls_vectors::MessagesTestVector>().verify();
      break;
    }

    default:
      return Status(StatusCode::INVALID_ARGUMENT, "Invalid test vector type");
  }

  if (error) {
    return Status(StatusCode::INVALID_ARGUMENT, error.value());
  }

  return Status::OK;
}

Status
MLSClientImpl::generate_test_vector(const GenerateTestVectorRequest* request,
                                    GenerateTestVectorResponse* reply)
{
  json j;
  switch (request->test_vector_type()) {
    case TestVectorType::TREE_MATH: {
      j = mls_vectors::TreeMathTestVector::create(request->n_leaves());
      break;
    }

    case TestVectorType::ENCRYPTION: {
      auto suite = static_cast<mls::CipherSuite::ID>(request->cipher_suite());
      j = mls_vectors::EncryptionTestVector::create(
        suite, request->n_leaves(), request->n_generations());
      break;
    }

    case TestVectorType::KEY_SCHEDULE: {
      auto suite = static_cast<mls::CipherSuite::ID>(request->cipher_suite());
      j =
        mls_vectors::KeyScheduleTestVector::create(suite, request->n_epochs());
      break;
    }

    case TestVectorType::TRANSCRIPT: {
      auto suite = static_cast<mls::CipherSuite::ID>(request->cipher_suite());
      j = mls_vectors::TranscriptTestVector::create(suite);
      break;
    }

    case TestVectorType::TREEKEM: {
      auto suite = static_cast<mls::CipherSuite::ID>(request->cipher_suite());
      j = mls_vectors::TreeKEMTestVector::create(suite, request->n_leaves());
      break;
    }

    case TestVectorType::MESSAGES: {
      j = mls_vectors::MessagesTestVector::create();
      break;
    }

    default:
      return Status(StatusCode::INVALID_ARGUMENT, "Invalid test vector type");
  }

  reply->set_test_vector(j.dump());
  return Status::OK;
}

// Ways to join a group
Status
MLSClientImpl::create_group(const CreateGroupRequest* request,
                            CreateGroupResponse* response)
{
  auto group_id = string_to_bytes(request->group_id());
  auto cipher_suite = mls_suite(request->cipher_suite());

  auto init_priv = mls::HPKEPrivateKey::generate(cipher_suite);
  auto sig_priv = mls::SignaturePrivateKey::generate(cipher_suite);
  auto cred = mls::Credential::basic({}, sig_priv.public_key);
  auto key_package =
    mls::KeyPackage(cipher_suite, init_priv.public_key, cred, sig_priv, {});

  auto state =
    mls::State(group_id, cipher_suite, init_priv, sig_priv, key_package, {});
  auto state_id = store_state(std::move(state), request->encrypt_handshake());

  response->set_state_id(state_id);
  return Status::OK;
}

Status
MLSClientImpl::create_key_package(const CreateKeyPackageRequest* request,
                                  CreateKeyPackageResponse* response)
{
  auto cipher_suite = mls_suite(request->cipher_suite());

  auto init_priv = mls::HPKEPrivateKey::generate(cipher_suite);
  auto sig_priv = mls::SignaturePrivateKey::generate(cipher_suite);
  auto cred = mls::Credential::basic({}, sig_priv.public_key);
  auto kp =
    mls::KeyPackage(cipher_suite, init_priv.public_key, cred, sig_priv, {});

  auto kp_data = tls::marshal(kp);
  auto join_id =
    store_join(std::move(init_priv), std::move(sig_priv), std::move(kp));

  response->set_transaction_id(join_id);
  response->set_key_package(bytes_to_string(kp_data));
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

  auto welcome_data = string_to_bytes(request->welcome());
  auto welcome = tls::get<mls::Welcome>(welcome_data);

  auto state =
    mls::State(join->init_priv, join->sig_priv, join->key_package, welcome, std::nullopt);
  auto state_id = store_state(std::move(state), request->encrypt_handshake());

  response->set_state_id(state_id);
  return Status::OK;
}

Status
MLSClientImpl::external_join(const ExternalJoinRequest* request,
                             ExternalJoinResponse* response)
{
  auto pgs_data = string_to_bytes(request->public_group_state());
  auto pgs = tls::get<mls::PublicGroupState>(pgs_data);

  auto init_priv = mls::HPKEPrivateKey::generate(pgs.cipher_suite);
  auto sig_priv = mls::SignaturePrivateKey::generate(pgs.cipher_suite);
  auto cred = mls::Credential::basic({}, sig_priv.public_key);
  auto kp =
    mls::KeyPackage(pgs.cipher_suite, init_priv.public_key, cred, sig_priv, {});

  auto leaf_secret = mls::random_bytes(pgs.cipher_suite.secret_size());
  auto [commit, state] =
    mls::State::external_join(leaf_secret, sig_priv, kp, pgs, std::nullopt);
  auto commit_data = tls::marshal(commit);
  auto state_id = store_state(std::move(state), request->encrypt_handshake());

  response->set_state_id(state_id);
  response->set_commit(bytes_to_string(commit_data));
  return Status::OK;
}

// Access information from a group state
Status
MLSClientImpl::public_group_state(CachedState& entry,
                                  const PublicGroupStateRequest* /* request */,
                                  PublicGroupStateResponse* response)
{
  auto pgs = tls::marshal(entry.state.public_group_state());
  response->set_public_group_state(bytes_to_string(pgs));
  return Status::OK;
}

Status
MLSClientImpl::state_auth(CachedState& entry,
                          const StateAuthRequest* /* request */,
                          StateAuthResponse* response)
{
  auto secret = entry.state.authentication_secret();
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
  auto ct = entry.state.protect(pt);
  auto ct_data = tls::marshal(ct);
  response->set_ciphertext(bytes_to_string(ct_data));
  return Status::OK;
}

Status
MLSClientImpl::unprotect(CachedState& entry,
                         const UnprotectRequest* request,
                         UnprotectResponse* response)
{
  auto ct_data = string_to_bytes(request->ciphertext());
  auto ct = tls::get<mls::MLSCiphertext>(ct_data);
  auto pt = entry.state.unprotect(ct);
  response->set_application_data(bytes_to_string(pt));
  return Status::OK;
}

// Operations on a running group
Status
MLSClientImpl::add_proposal(CachedState& entry,
                            const AddProposalRequest* request,
                            ProposalResponse* response)
{
  auto key_package_data = string_to_bytes(request->key_package());
  auto key_package = tls::get<mls::KeyPackage>(key_package_data);

  auto proposal = entry.state.add(key_package);

  response->set_proposal(entry.marshal(proposal));
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
    auto pt = entry.unmarshal(request->by_reference(i));
    auto should_be_null = entry.state.handle(pt);
    if (should_be_null) {
      throw std::runtime_error("Commit included among proposals");
    }
  }

  auto inline_proposals = std::vector<mls::Proposal>(request->by_value_size());
  for (size_t i = 0; i < inline_proposals.size(); i++) {
    auto pt = entry.unmarshal(request->by_value(i));
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

  auto leaf_secret =
    mls::random_bytes(entry.state.cipher_suite().secret_size());
  auto [commit, welcome, next] =
    entry.state.commit(leaf_secret, mls::CommitOpts{inline_proposals, true});

  auto next_id = store_state(std::move(next), entry.encrypt_handshake);

  auto commit_data = entry.marshal(commit);
  response->set_commit(commit_data);

  entry.pending_commit = commit_data;
  entry.pending_state_id = next_id;

  auto welcome_data = tls::marshal(welcome);
  response->set_welcome(bytes_to_string(welcome_data));

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
    auto pt = entry.unmarshal(request->proposal(i));
    auto should_be_null = entry.state.handle(pt);
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
  auto next_id = store_state(std::move(next), entry.encrypt_handshake);
  response->set_state_id(next_id);
  return Status::OK;
}

Status
MLSClientImpl::handle_external_commit(
  CachedState& entry,
  const HandleExternalCommitRequest* request,
  HandleExternalCommitResponse* response)
{
  auto commit_data = string_to_bytes(request->commit());
  auto commit = tls::get<mls::MLSPlaintext>(commit_data);
  auto should_be_next = entry.state.handle(commit);
  if (!should_be_next) {
    throw std::runtime_error("Commit failed to produce a new state");
  }

  auto& next = opt::get(should_be_next);
  auto next_id = store_state(std::move(next), entry.encrypt_handshake);
  response->set_state_id(next_id);
  return Status::OK;
}
