#include <doctest/doctest.h>
#include <mls/log.h>

using namespace std::literals::string_literals;
using namespace mls;
using log::Log;

enum struct Level
{
  invalid,
  fatal,
  error,
  info,
  warn,
  debug,
  crypto,
};

struct TestSink : public log::Sink
{
  Level last_level = Level::invalid;
  std::string last_mod;
  std::string last_message;

  ~TestSink() override = default;

  void record(Level level, const std::string& mod, const std::string& message)
  {
    last_level = level;
    last_mod = mod;
    last_message = message;
  }

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define TEST_SINK_METHOD(level)                                                \
  void level(const std::string& mod, const std::string& message) override      \
  {                                                                            \
    record(Level::level, mod, message);                                        \
  }

  TEST_SINK_METHOD(fatal)
  TEST_SINK_METHOD(error)
  TEST_SINK_METHOD(info)
  TEST_SINK_METHOD(warn)
  TEST_SINK_METHOD(debug)
  TEST_SINK_METHOD(crypto)
};

TEST_CASE("Logging")
{
  const auto mod = "test"s;
  auto sink = std::make_shared<TestSink>();
  Log::set_sink(sink);

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define TEST_LOG_LEVEL(level)                                                  \
  {                                                                            \
    auto message = std::string(#level);                                        \
    Log::level(mod, message);                                                  \
    REQUIRE(sink->last_level == Level::level);                                 \
    REQUIRE(sink->last_mod == mod);                                            \
    REQUIRE(sink->last_message == message);                                    \
  }

  TEST_LOG_LEVEL(fatal)
  TEST_LOG_LEVEL(error)
  TEST_LOG_LEVEL(info)
  TEST_LOG_LEVEL(warn)
  TEST_LOG_LEVEL(debug)
  TEST_LOG_LEVEL(crypto)
}
