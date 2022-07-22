#include <memory>
#include <sstream>
#include <string>

namespace mls {
namespace log {

struct Sink
{
  virtual ~Sink() = default;
  virtual void fatal(const std::string& /*mod*/, const std::string& /*msg*/) {}
  virtual void error(const std::string& /*mod*/, const std::string& /*msg*/) {}
  virtual void info(const std::string& /*mod*/, const std::string& /*msg*/) {}
  virtual void warn(const std::string& /*mod*/, const std::string& /*msg*/) {}
  virtual void debug(const std::string& /*mod*/, const std::string& /*msg*/) {}
  virtual void crypto(const std::string& /*mod*/, const std::string& /*msg*/) {}
};

struct Log
{
private:
  static std::shared_ptr<Sink> sink;

  template<typename... Ts>
  static std::string print(const Ts&... vals)
  {
    auto ss = std::stringstream();
    (ss << ... << vals);
    return ss.str();
  }

public:
  static void set_sink(std::shared_ptr<Sink> sink_in);
  static void remove_sink();

  template<typename... Ts>
  static void fatal(const std::string& mod, const Ts&... vals)
  {
    if (sink) {
      sink->fatal(mod, print(vals...));
    }
  }

  template<typename... Ts>
  static void error(const std::string& mod, const Ts&... vals)
  {
    if (sink) {
      sink->error(mod, print(vals...));
    }
  }

  template<typename... Ts>
  static void info(const std::string& mod, const Ts&... vals)
  {
    if (sink) {
      sink->info(mod, print(vals...));
    }
  }

  template<typename... Ts>
  static void warn(const std::string& mod, const Ts&... vals)
  {
    if (sink) {
      sink->warn(mod, print(vals...));
    }
  }

  template<typename... Ts>
  static void debug(const std::string& mod, const Ts&... vals)
  {
    if (sink) {
      sink->debug(mod, print(vals...));
    }
  }

// TODO(rlb) Enable this value to be configured
#define ENABLE_LOG_CRYPTO
#ifdef ENABLE_LOG_CRYPTO
  template<typename... Ts>
  static void crypto(const std::string& mod, const Ts&... vals)
  {
    if (sink) {
      sink->crypto(mod, print(vals...));
    }
  }
#else
  template<typename... Ts>
  static void crypto(const std::string& /*mod*/, const Ts&... /*vals*/)
  {
  }
#endif
};

} // namespace log
} // namespace mls
