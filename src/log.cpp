#include <mls/log.h>

namespace mls {
namespace log {

std::shared_ptr<Sink> Log::sink = nullptr;

void
Log::set_sink(std::shared_ptr<Sink> sink_in)
{
  sink = sink_in;
}

void
Log::remove_sink()
{
  sink = nullptr;
}

} // namespace log
} // namespace mls
