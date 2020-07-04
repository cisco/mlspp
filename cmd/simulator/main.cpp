/*

Input format:

{
  "initial_size": n,
  "steps": [
    {"action": "add",    "by": n}
    {"action": "update", "by": n},
    {"action": "remove", "by": n, "of": b},
  ]
}

Output format (one per line):

{
  "sender": { ...crypto metrics... },
  "receivers": [
    { ...crypto metrics... },
    { ...crypto metrics... },
    { ...crypto metrics... },
    ...
  ]
}

*/

#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "crypto.h"
#include "session.h"

#include "autojson.h"
#include "json.hpp"

using nlohmann::json;

const std::string kActionAdd = "add";
const std::string kActionUpdate = "update";
const std::string kActionRemove = "remove";

enum struct Action
{
  add,
  update,
  remove
};

NLOHMANN_JSON_SERIALIZE_ENUM(Action,
                             {
                               { Action::add, "add" },
                               { Action::update, "update" },
                               { Action::remove, "remove" },
                             })

struct Step
{
  Action action;
  uint32_t by;
  uint32_t of;

  JSON_SERIALIZABLE(action, by, of);
};

struct Script
{
  size_t initial_size;
  std::vector<Step> steps;

  JSON_SERIALIZABLE(initial_size, steps);
};

std::string
read_file(const std::string& filename)
{
  std::ifstream file(filename, std::ios::binary);
  file.unsetf(std::ios::skipws);

  std::streampos fileSize;
  file.seekg(0, std::ios::end);
  fileSize = file.tellg();
  file.seekg(0, std::ios::beg);

  std::vector<uint8_t> vec;
  vec.reserve(fileSize);
  vec.insert(vec.begin(),
             std::istream_iterator<uint8_t>(file),
             std::istream_iterator<uint8_t>());

  return std::string(vec.begin(), vec.end());
}

namespace nlohmann {
template<>
struct adl_serializer<mls::CryptoMetrics::Report>
{
  static void to_json(json& j, const mls::CryptoMetrics::Report& report)
  {
    j = json{
      { "fixed_base_dh", report.fixed_base_dh },
      { "var_base_dh", report.var_base_dh },
      { "digest", report.digest },
      { "hmac", report.hmac },
    };
  }
};
} // namespace nlohmann

struct StepMetrics
{
  mls::CryptoMetrics::Report sender;
  std::vector<mls::CryptoMetrics::Report> receivers;

  JSON_SERIALIZABLE(sender, receivers);
};

class Simulation
{
private:
  mls::CipherSuite suite;
  mls::SignatureScheme scheme;
  std::vector<std::optional<mls::Session>> sessions;

public:
  Simulation(mls::CipherSuite suite_in, mls::SignatureScheme scheme_in)
    : suite(suite_in)
    , scheme(scheme_in)
  {}

  mls::bytes random() const { return mls::random_bytes(32); }

  mls::Session::InitInfo fresh_init_info() const
  {
    auto secret = mls::random_bytes(32);
    auto init = mls::HPKEPrivateKey::derive(suite, secret);
    auto priv = mls::SignaturePrivateKey::generate(scheme);
    auto id = random();
    auto cred = mls::Credential::basic(id, priv.public_key());
    auto kp = mls::KeyPackage{ suite, init.public_key(), cred, priv };
    return { secret, priv, kp };
  }

  std::vector<mls::CryptoMetrics::Report> broadcast(const mls::bytes& message)
  {
    std::vector<mls::CryptoMetrics::Report> reports;
    for (auto& session : sessions) {
      if (!session.has_value()) {
        reports.emplace_back();
        continue;
      }

      mls::CryptoMetrics::reset();
      session.value().handle(message);
      reports.push_back(mls::CryptoMetrics::snapshot());
    }

    return reports;
  }

  // XXX: Right now, this is by "create one-member and add"; it should be done
  // via direct initialization (Init)
  void init(size_t initial_size)
  {
    auto group_id = random();
    auto info0 = fresh_init_info();
    auto info1 = fresh_init_info();
    auto [session0, welcome1] =
      mls::Session::start(group_id, { info0 }, { info1.key_package }, random());
    auto session1 = mls::Session::join({ info1 }, welcome1);

    sessions = { session0, session1 };
    while (sessions.size() < initial_size) {
      auto info = fresh_init_info();
      auto [welcome, add] = sessions[0].value().add(random(), info.key_package);
      broadcast(add);
      sessions.emplace_back(mls::Session::join({ info }, welcome));
    }
  }

  // TODO Add at the leftmost blank slot instead of at the right edge
  StepMetrics add(uint32_t by)
  {
    StepMetrics report{};
    auto info = fresh_init_info();

    mls::CryptoMetrics::reset();
    auto [welcome, add] = sessions[by].value().add(random(), info.key_package);
    report.sender = mls::CryptoMetrics::snapshot();
    report.receivers = broadcast(add);

    mls::CryptoMetrics::reset();
    auto new_session = mls::Session::join({ info }, welcome);
    report.receivers.push_back(mls::CryptoMetrics::snapshot());
    sessions.emplace_back(new_session);

    return report;
  }

  StepMetrics update(uint32_t by)
  {
    StepMetrics report{};
    mls::CryptoMetrics::reset();
    auto update = sessions[by].value().update(random());
    report.sender = mls::CryptoMetrics::snapshot();
    report.receivers = broadcast(update);
    return report;
  }

  StepMetrics remove(uint32_t by, uint32_t of)
  {
    StepMetrics report{};
    mls::CryptoMetrics::reset();
    auto update = sessions[by].value().remove(random(), of);
    report.sender = mls::CryptoMetrics::snapshot();
    sessions[of] = std::nullopt;
    report.receivers = broadcast(update);
    return report;
  }
};

int
main(int argc, char** argv)
{
  const auto suite = mls::CipherSuite::X25519_SHA256_AES128GCM;
  const auto scheme = mls::SignatureScheme::Ed25519;

  if (argc < 2) {
    std::cout << "Usage: simulator <script.json>" << std::endl;
  }

  std::string filename(argv[1]);
  auto script_json = read_file(filename);
  auto script = json::parse(script_json).get<Script>();

  // Initialize a set of sessions
  Simulation sim(suite, scheme);
  sim.init(script.initial_size);

  // Follow the steps in the script
  for (const auto& step : script.steps) {
    StepMetrics report;
    switch (step.action) {
      case Action::add:
        report = sim.add(step.by);
        break;

      case Action::update:
        report = sim.update(step.by);
        break;

      case Action::remove:
        report = sim.remove(step.by, step.of);
        break;
    }

    std::cout << json(report) << std::endl;
  }

  std::cout << "Done" << std::endl; // XXX
}
