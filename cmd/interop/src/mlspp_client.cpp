
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include <gflags/gflags.h>
#include <grpcpp/grpcpp.h>

#include <mls/crypto.h>
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

#if 0
// XXX(RLB): Normally I wouldn't want `#if 0` code hanging around.  But these
// will be useful once we start passing MLS messages back and forth.
static std::string
bytes_to_string(const std::vector<uint8_t>& data)
{
  return { data.begin(), data.end() };
}

static std::vector<uint8_t>
string_to_bytes(const std::string& str)
{
  return { str.begin(), str.end() };
}
#endif // 0

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
