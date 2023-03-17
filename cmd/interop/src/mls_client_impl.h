#pragma once

#include <mls/crypto.h>
#include <mls/state.h>
#include <mls_vectors/mls_vectors.h>

#include "mls_client.grpc.pb.h"

using grpc::ServerContext;
using grpc::Status;
using namespace mls_client;

class MLSClientImpl final : public MLSClient::Service
{
  // gRPC methods
  Status Name(ServerContext* context,
              const NameRequest* request,
              NameResponse* reply) override;

  Status SupportedCiphersuites(ServerContext* context,
                               const SupportedCiphersuitesRequest* request,
                               SupportedCiphersuitesResponse* reply) override;

  // Ways to become a member of a group
  Status CreateGroup(ServerContext* context,
                     const CreateGroupRequest* request,
                     CreateGroupResponse* response) override;
  Status CreateKeyPackage(ServerContext* context,
                          const CreateKeyPackageRequest* request,
                          CreateKeyPackageResponse* response) override;
  Status JoinGroup(ServerContext* context,
                   const JoinGroupRequest* request,
                   JoinGroupResponse* response) override;
  Status ExternalJoin(ServerContext* context,
                      const ExternalJoinRequest* request,
                      ExternalJoinResponse* response) override;

  // Access information from a group state
  Status GroupInfo(ServerContext* context,
                   const GroupInfoRequest* request,
                   GroupInfoResponse* response) override;
  Status StateAuth(ServerContext* context,
                   const StateAuthRequest* request,
                   StateAuthResponse* response) override;
  Status Export(ServerContext* context,
                const ExportRequest* request,
                ExportResponse* response) override;
  Status Protect(ServerContext* context,
                 const ProtectRequest* request,
                 ProtectResponse* response) override;
  Status Unprotect(ServerContext* context,
                   const UnprotectRequest* request,
                   UnprotectResponse* response) override;
  Status StorePSK(ServerContext* context,
                  const StorePSKRequest* request,
                  StorePSKResponse* response) override;

  // Operations using a group state
  Status AddProposal(ServerContext* context,
                     const AddProposalRequest* request,
                     ProposalResponse* response) override;
  Status UpdateProposal(ServerContext* context,
                        const UpdateProposalRequest* request,
                        ProposalResponse* response) override;
  Status RemoveProposal(ServerContext* context,
                        const RemoveProposalRequest* request,
                        ProposalResponse* response) override;
  Status ExternalPSKProposal(ServerContext* context,
                             const ExternalPSKProposalRequest* request,
                             ProposalResponse* response) override;
  Status ResumptionPSKProposal(ServerContext* context,
                               const ResumptionPSKProposalRequest* request,
                               ProposalResponse* response) override;
  Status GroupContextExtensionsProposal(
    ServerContext* context,
    const GroupContextExtensionsProposalRequest* request,
    ProposalResponse* response) override;

  Status Commit(ServerContext* context,
                const CommitRequest* request,
                CommitResponse* response) override;
  Status HandleCommit(ServerContext* context,
                      const HandleCommitRequest* request,
                      HandleCommitResponse* response) override;
  Status HandlePendingCommit(ServerContext* context,
                             const HandlePendingCommitRequest* request,
                             HandleCommitResponse* response) override;

private:
  // Wrapper for methods that rely on state
  template<typename Req, typename F>
  Status state_wrap(const Req* req, F&& f);

  // Cached join transactions
  struct CachedJoin
  {
    mls::HPKEPrivateKey init_priv;
    mls::HPKEPrivateKey leaf_priv;
    mls::SignaturePrivateKey sig_priv;
    mls::KeyPackage key_package;
    std::map<bytes, bytes> external_psks;
  };

  std::map<uint32_t, CachedJoin> join_cache;

  uint32_t store_join(mls::HPKEPrivateKey&& init_priv,
                      mls::HPKEPrivateKey&& leaf_priv,
                      mls::SignaturePrivateKey&& sig_priv,
                      mls::KeyPackage&& kp);
  CachedJoin* load_join(uint32_t join_id);

  // Cached group state
  struct CachedState
  {
    mls::State state;
    bool encrypt_handshake;
    mls::MessageOpts message_opts() const;

    std::optional<std::string> pending_commit;
    std::optional<uint32_t> pending_state_id;
    void reset_pending();

    // Marshal/unmarshal with encryption as required
    std::string marshal(const mls::MLSMessage& msg);
    mls::MLSMessage unmarshal(const std::string& wire);
  };

  std::map<uint32_t, CachedState> state_cache;

  uint32_t store_state(mls::State&& state, bool encrypt_handshake);
  CachedState* load_state(uint32_t state_id);
  CachedState* find_state(const bytes& group_id, const mls::epoch_t epoch);
  void remove_state(uint32_t state_id);

  mls::LeafIndex find_member(const mls::State& state,
                             const std::string& identity);
  mls::Proposal proposal_from_description(mls::State& state,
                                          const ProposalDescription& desc);

  // Ways to join a group
  Status create_group(const CreateGroupRequest* request,
                      CreateGroupResponse* response);
  Status create_key_package(const CreateKeyPackageRequest* request,
                            CreateKeyPackageResponse* response);
  Status join_group(const JoinGroupRequest* request,
                    JoinGroupResponse* response);
  Status external_join(const ExternalJoinRequest* request,
                       ExternalJoinResponse* response);

  // Access information from a group state
  Status group_info(CachedState& entry,
                    const GroupInfoRequest* request,
                    GroupInfoResponse* response);
  Status state_auth(CachedState& entry,
                    const StateAuthRequest* request,
                    StateAuthResponse* response);
  Status do_export(CachedState& entry,
                   const ExportRequest* request,
                   ExportResponse* response);
  Status protect(CachedState& entry,
                 const ProtectRequest* request,
                 ProtectResponse* response);
  Status unprotect(CachedState& entry,
                   const UnprotectRequest* request,
                   UnprotectResponse* response);

  // Operations on a running group
  Status add_proposal(CachedState& entry,
                      const AddProposalRequest* request,
                      ProposalResponse* response);
  Status update_proposal(CachedState& entry,
                         const UpdateProposalRequest* request,
                         ProposalResponse* response);
  Status remove_proposal(CachedState& entry,
                         const RemoveProposalRequest* request,
                         ProposalResponse* response);
  Status external_psk_proposal(CachedState& entry,
                               const ExternalPSKProposalRequest* request,
                               ProposalResponse* response);
  Status resumption_psk_proposal(CachedState& entry,
                                 const ResumptionPSKProposalRequest* request,
                                 ProposalResponse* response);
  Status group_context_extensions_proposal(
    CachedState& entry,
    const GroupContextExtensionsProposalRequest* request,
    ProposalResponse* response);

  Status commit(CachedState& entry,
                const CommitRequest* request,
                CommitResponse* response);
  Status handle_commit(CachedState& entry,
                       const HandleCommitRequest* request,
                       HandleCommitResponse* response);
  Status handle_pending_commit(CachedState& entry,
                               const HandlePendingCommitRequest* request,
                               HandleCommitResponse* response);
};
