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

  // External Proposals
  Status NewMemberAddProposal(ServerContext* context,
                              const NewMemberAddProposalRequest* request,
                              NewMemberAddProposalResponse* response) override;
  Status CreateExternalSigner(ServerContext* context,
                              const CreateExternalSignerRequest* request,
                              CreateExternalSignerResponse* response) override;
  Status AddExternalSigner(ServerContext* context,
                           const AddExternalSignerRequest* request,
                           ProposalResponse* response) override;
  Status ExternalSignerProposal(ServerContext* context,
                                const ExternalSignerProposalRequest* request,
                                ProposalResponse* response) override;

  // Reinitialization
  Status ReInitProposal(ServerContext* context,
                        const ReInitProposalRequest* request,
                        ProposalResponse* response) override;
  Status ReInitCommit(ServerContext* context,
                      const CommitRequest* request,
                      CommitResponse* response) override;
  Status HandlePendingReInitCommit(
    ServerContext* context,
    const HandlePendingCommitRequest* request,
    HandleReInitCommitResponse* response) override;
  Status HandleReInitCommit(ServerContext* context,
                            const HandleCommitRequest* request,
                            HandleReInitCommitResponse* response) override;
  Status ReInitWelcome(ServerContext* context,
                       const ReInitWelcomeRequest* request,
                       CreateSubgroupResponse* response) override;
  Status HandleReInitWelcome(ServerContext* context,
                             const HandleReInitWelcomeRequest* request,
                             JoinGroupResponse* response) override;

  // Subgroup branching
  Status CreateBranch(ServerContext* context,
                      const CreateBranchRequest* request,
                      CreateSubgroupResponse* response) override;
  Status HandleBranch(ServerContext* context,
                      const HandleBranchRequest* request,
                      HandleBranchResponse* response) override;

  // Cleanup
  Status Free(ServerContext* context,
              const FreeRequest* request,
              FreeResponse* response) override;

private:
  // Wrapper for methods that rely on state
  template<typename Req, typename F>
  Status state_wrap(const Req* req, F&& f);

  struct KeyPackageWithSecrets
  {
    mls::HPKEPrivateKey init_priv;
    mls::HPKEPrivateKey encryption_priv;
    mls::SignaturePrivateKey signature_priv;
    mls::KeyPackage key_package;
  };

  KeyPackageWithSecrets new_key_package(mls::CipherSuite cipher_suite,
                                        const bytes& identity);

  // Cached join transactions
  struct CachedJoin
  {
    KeyPackageWithSecrets kp_priv;
    std::map<bytes, bytes> external_psks;
  };

  std::map<uint32_t, CachedJoin> join_cache;

  uint32_t store_join(KeyPackageWithSecrets&& kp);
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

  mls::LeafIndex find_member(const mls::TreeKEMPublicKey& tree,
                             const std::string& identity);
  mls::Proposal proposal_from_description(mls::CipherSuite suite,
                                          const bytes& group_id,
                                          const mls::TreeKEMPublicKey& tree,
                                          const ProposalDescription& desc);

  // Cached external signers
  struct CachedSigner
  {
    mls::SignaturePrivateKey signature_priv;
  };

  std::map<uint32_t, CachedSigner> signer_cache;

  uint32_t store_signer(mls::SignaturePrivateKey&& signature_priv);
  CachedSigner* load_signer(uint32_t signer_id);

  // Cached ReInit
  struct CachedReInit
  {
    KeyPackageWithSecrets kp_priv;
    mls::State::Tombstone tombstone;
    bool encrypt_handshake;
  };

  std::map<uint32_t, CachedReInit> reinit_cache;

  uint32_t store_reinit(KeyPackageWithSecrets&& kp_priv,
                        mls::State::Tombstone&& tombstone,
                        bool encrypt_handshake);
  CachedReInit* load_reinit(uint32_t reinit_id);
  void remove_reinit(uint32_t reinit_id);

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

  Status new_member_add_proposal(const NewMemberAddProposalRequest* request,
                                 NewMemberAddProposalResponse* response);
  Status create_external_signer(const CreateExternalSignerRequest* request,
                                CreateExternalSignerResponse* response);
  Status add_external_signer(CachedState& entry,
                             const AddExternalSignerRequest* request,
                             ProposalResponse* response);
  Status external_signer_proposal(const ExternalSignerProposalRequest* request,
                                  ProposalResponse* response);

  // Reinitialization
  Status reinit_proposal(CachedState& entry,
                         const ReInitProposalRequest* request,
                         ProposalResponse* response);
  Status reinit_commit(CachedState& entry,
                       const CommitRequest* request,
                       CommitResponse* response);
  Status handle_pending_reinit_commit(CachedState& entry,
                                      const HandlePendingCommitRequest* request,
                                      HandleReInitCommitResponse* response);
  Status handle_reinit_commit(CachedState& entry,
                              const HandleCommitRequest* request,
                              HandleReInitCommitResponse* response);
  Status reinit_welcome(const ReInitWelcomeRequest* request,
                        CreateSubgroupResponse* response);
  Status handle_reinit_welcome(const HandleReInitWelcomeRequest* request,
                               JoinGroupResponse* response);

  // Subgroup branching
  Status create_branch(CachedState& entry,
                       const CreateBranchRequest* request,
                       CreateSubgroupResponse* response);
  Status handle_branch(CachedState& entry,
                       const HandleBranchRequest* request,
                       HandleBranchResponse* response);
};
