#include <memory>
#include <string>
#include <sstream>
#include <iostream>

#include <gflags/gflags.h>
#include <grpcpp/grpcpp.h>

#include <tls/tls_syntax.h>
#include <mls/crypto.h>
#include <mls_vectors/mls_vectors.h>

#include "mls_client.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using grpc::StatusCode;
using namespace mls_client;

static constexpr char implementation_name[] = "mlspp";

static std::string
bytes_to_string(const std::vector<uint8_t>& data) {
  return {data.begin(), data.end()};
}

static std::vector<uint8_t>
string_to_bytes(const std::string& str) {
  return {str.begin(), str.end()};
}

class MLSClientImpl final : public MLSClient::Service
{
  // Map C++ exceptions to gRPC errors
  Status catch_wrap(std::function<Status()>&& f) {
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

  Status SupportedCiphersuites(ServerContext* /* context */,
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
    auto tv_data = string_to_bytes(request->test_vector());
    auto error = std::optional<std::string>();
    switch (request->test_vector_type()) {
      case TestVectorType::TREE_MATH: {
          error = tls::get<mls_vectors::TreeMathTestVector>(tv_data).verify();
          break;
      }

      case TestVectorType::ENCRYPTION: {
          error = tls::get<mls_vectors::EncryptionTestVector>(tv_data).verify();
          break;
      }

      case TestVectorType::KEY_SCHEDULE: {
          error = tls::get<mls_vectors::KeyScheduleTestVector>(tv_data).verify();
          break;
      }

      case TestVectorType::TREEKEM: {
          auto tv = tls::get<mls_vectors::TreeKEMTestVector>(tv_data);
          tv.initialize_trees();
          error = tv.verify();
          break;
      }

      case TestVectorType::MESSAGES: {
          error = tls::get<mls_vectors::MessagesTestVector>(tv_data).verify();
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
    std::vector<uint8_t> tv_data;
    switch (request->test_vector_type()) {
      case TestVectorType::TREE_MATH: {
          auto tv = mls_vectors::TreeMathTestVector::create(request->n_leaves());
          tv_data = tls::marshal(tv);
          break;
      }

      case TestVectorType::ENCRYPTION: {
          auto suite = static_cast<mls::CipherSuite::ID>(request->cipher_suite());
          auto tv = mls_vectors::EncryptionTestVector::create(suite, request->n_leaves(), request->n_generations());
          tv_data = tls::marshal(tv);
          break;
      }

      case TestVectorType::KEY_SCHEDULE: {
          auto suite = static_cast<mls::CipherSuite::ID>(request->cipher_suite());
          auto tv = mls_vectors::KeyScheduleTestVector::create(suite, request->n_epochs());
          tv_data = tls::marshal(tv);
          break;
      }

      case TestVectorType::TREEKEM: {
          auto suite = static_cast<mls::CipherSuite::ID>(request->cipher_suite());
          auto tv = mls_vectors::TreeKEMTestVector::create(suite, request->n_leaves());
          tv_data = tls::marshal(tv);
          break;
      }

      case TestVectorType::MESSAGES: {
          auto tv = mls_vectors::MessagesTestVector::create();
          tv_data = tls::marshal(tv);
          break;
      }

      default:
        return Status(StatusCode::INVALID_ARGUMENT, "Invalid test vector type");
    }

    reply->set_test_vector(bytes_to_string(tv_data));
    return Status::OK;
  }
};

DEFINE_uint64(port, 50051, "Port to listen on");

int
main(int argc, char *argv[])
{
  gflags::ParseCommandLineFlags(&argc, &argv, true);

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
