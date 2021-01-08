#include <sstream>
#include <string>

namespace mls {
namespace log {

struct Sink
{
  virtual ~Sink() = default;
  virtual void fatal(const std::string& mod, const std::string& message) = 0;
  virtual void error(const std::string& mod, const std::string& message) = 0;
  virtual void info(const std::string& mod, const std::string& message) = 0;
  virtual void warn(const std::string& mod, const std::string& message) = 0;
  virtual void debug(const std::string& mod, const std::string& message) = 0;
  virtual void crypto(const std::string& mod, const std::string& message) = 0;
};

struct Log
{
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
  {}
#endif

private:
  static std::shared_ptr<Sink> sink;

  // XXX(RLB) C++17 parameter pack expansion (str << ... << vals) causes errors
  // when used with custom operator<<, as for bytes.  So we define our own
  // expansion routine here.
  template<typename T>
  static void concat(std::ostream& str, const T& val)
  {
    str << val;
  }

  template<typename T, typename... Ts>
  static void concat(std::ostream& str, const T& val, const Ts&... more)
  {
    str << val;
    concat(str, more...);
  }

  template<typename... Ts>
  static std::string print(const Ts&... vals)
  {
    auto ss = std::stringstream();
    concat(ss, vals...);
    return ss.str();
  }
};

} // namespace log
} // namespace mls
