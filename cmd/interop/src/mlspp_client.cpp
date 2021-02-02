
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include <gflags/gflags.h>
#include <grpcpp/grpcpp.h>

#include <mls/crypto.h>
#include <mls/state.h>
#include <mls_vectors/mls_vectors.h>

#include "json_details.h"
#include "mls_client.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using grpc::StatusCode;
using nlohmann::json;
using namespace mls_client;

static constexpr char implementation_name[] = "mlspp";

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

static inline mls::CipherSuite mls_suite(uint32_t suite_id)
{
  return static_cast<mls::CipherSuite::ID>(suite_id);
}

class MLSClientImpl final : public MLSClient::Service
{
  // Map C++ exceptions to gRPC errors
  Status catch_wrap(std::function<Status()>&& f)
  {
    try {
      return f();
    } catch (const std::exception& e) {
      return Status(StatusCode::INTERNAL, e.what());
    }
  }

  // gRPC methods
  Status Name(ServerContext* /* context */,
              const NameRequest* /* request */,
              NameResponse* reply) override
  {
    reply->set_name(implementation_name);
    return Status::OK;
  }

  Status SupportedCiphersuites(
    ServerContext* /* context */,
    const SupportedCiphersuitesRequest* /* request */,
    SupportedCiphersuitesResponse* reply) override
  {
    reply->clear_ciphersuites();
    for (const auto suite : mls::all_supported_suites) {
      reply->add_ciphersuites(static_cast<uint32_t>(suite));
    }
    return Status::OK;
  }

  Status GenerateTestVector(ServerContext* /* context */,
                            const GenerateTestVectorRequest* request,
                            GenerateTestVectorResponse* reply) override
  {
    return catch_wrap([=]() { return generate_test_vector(request, reply); });
  }

  Status VerifyTestVector(ServerContext* /* context */,
                          const VerifyTestVectorRequest* request,
                          VerifyTestVectorResponse* /* reply */) override
  {
    return catch_wrap([=]() { return verify_test_vector(request); });
  }

  Status CreateGroup(ServerContext* /* context */,
                     const CreateGroupRequest* request,
                     CreateGroupResponse* response) override
  {
    return catch_wrap([=]() { return create_group(request, response); });
  }

  Status CreateKeyPackage(ServerContext* /* context */,
                          const CreateKeyPackageRequest* request,
                          CreateKeyPackageResponse* response) override
  {
    return catch_wrap([=]() { return create_key_package(request, response); });
  }

  private:

  // Fallible method implementations, wrapped before being exposed to gRPC
  Status verify_test_vector(const VerifyTestVectorRequest* request)
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

  Status generate_test_vector(const GenerateTestVectorRequest* request,
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
        j = mls_vectors::KeyScheduleTestVector::create(suite,
                                                       request->n_epochs());
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


  Status create_group(const CreateGroupRequest* request,
                      CreateGroupResponse* response)
  {
    auto group_id = string_to_bytes(request->group_id());
    auto cipher_suite = mls_suite(request->cipher_suite());

    auto init_priv = mls::HPKEPrivateKey::generate(cipher_suite);
    auto sig_priv = mls::SignaturePrivateKey::generate(cipher_suite);
    auto cred = mls::Credential::basic({}, sig_priv.public_key);
    auto key_package = mls::KeyPackage(cipher_suite, init_priv.public_key, cred, sig_priv, {});

    auto state = mls::State(group_id, cipher_suite, init_priv, sig_priv, key_package);
    auto state_id = store_state(std::move(state), request->encrypt_handshake());

    response->set_state_id(state_id);
    return Status::OK;
  }

  Status create_key_package(const CreateKeyPackageRequest* request,
                            CreateKeyPackageResponse* response)
  {
    auto cipher_suite = mls_suite(request->cipher_suite());

    auto init_priv = mls::HPKEPrivateKey::generate(cipher_suite);
    auto sig_priv = mls::SignaturePrivateKey::generate(cipher_suite);
    auto cred = mls::Credential::basic({}, sig_priv.public_key);
    auto kp = mls::KeyPackage(cipher_suite, init_priv.public_key, cred, sig_priv, {});

    auto kp_data = tls::marshal(kp);
    auto join_id = store_join(std::move(init_priv), std::move(sig_priv), std::move(kp));

    response->set_transaction_id(join_id);
    response->set_key_package(bytes_to_string(kp_data));
    return Status::OK;
  }

  // Cached join transactions
  struct CachedJoin {
    mls::HPKEPrivateKey init_priv;
    mls::SignaturePrivateKey sig_priv;
    mls::KeyPackage key_package;
  };

  std::map<uint32_t, CachedJoin> join_cache;

  uint32_t store_join(mls::HPKEPrivateKey&& init_priv, mls::SignaturePrivateKey&& sig_priv, mls::KeyPackage&& kp) {
    auto join_id = tls::get<uint32_t>(kp.hash());
    auto entry = CachedJoin{std::move(init_priv), std::move(sig_priv), std::move(kp)};
    join_cache.emplace(std::make_pair(join_id, std::move(entry)));
    return join_id;
  }

  CachedJoin* load_join(uint32_t join_id) {
    if (join_cache.count(join_id) == 0) {
      return nullptr;
    }
    return &join_cache.at(join_id);
  }

  // Cached group state
  struct CachedState {
    mls::State state;
    bool encrypt_handshake;
  };

  std::map<uint32_t, CachedState> state_cache;

  uint32_t store_state(mls::State&& state, bool encrypt_handshake) {
    auto state_id = tls::get<uint32_t>(state.authentication_secret());
    auto entry = CachedState{std::move(state), encrypt_handshake};
    state_cache.emplace(std::make_pair(state_id, std::move(entry)));
    return state_id;
  }

  CachedState* load_state(uint32_t state_id) {
    if (state_cache.count(state_id) == 0) {
      return nullptr;
    }
    return &state_cache.at(state_id);
  }
};

json
make_sample(uint64_t type)
{
  auto suite = mls::CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519;
  auto n = 5;
  switch (type) {
    case TestVectorType::TREE_MATH:
      return mls_vectors::TreeMathTestVector::create(n);

    case TestVectorType::ENCRYPTION:
      return mls_vectors::EncryptionTestVector::create(suite, n, n);

    case TestVectorType::KEY_SCHEDULE:
      return mls_vectors::KeyScheduleTestVector::create(suite, n);

    case TestVectorType::TRANSCRIPT:
      return mls_vectors::TranscriptTestVector::create(suite);

    case TestVectorType::TREEKEM:
      return mls_vectors::TreeKEMTestVector::create(suite, n);

    case TestVectorType::MESSAGES:
      return mls_vectors::MessagesTestVector::create();

    default:
      return nullptr;
  }
}

void
print_sample(uint64_t type)
{
  auto j = make_sample(type);
  if (j.is_null()) {
    std::cout << "Invalid test vector type" << std::endl;
    return;
  }

  std::cout << j.dump(2) << std::endl;
}

#define NO_SAMPLE 0xffffffffffffffff
DEFINE_uint64(sample, NO_SAMPLE, "Generate a sample JSON file (by enum value)");
DEFINE_uint64(port, 50001, "Listen for gRPC on this port");

int
main(int argc, char* argv[])
{
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  if (FLAGS_sample != NO_SAMPLE) {
    print_sample(FLAGS_sample);
    return 0;
  }

  auto service = MLSClientImpl{};
  auto server_address = (std::stringstream{} << "0.0.0.0:" << FLAGS_port).str();

  grpc::EnableDefaultHealthCheckService(true);
  ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(&service);

  std::cout << "Listening on " << server_address << std::endl;
  std::unique_ptr<Server> server(builder.BuildAndStart());
  server->Wait();

  return 0;
}
