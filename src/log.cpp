#include <mls/log.h>

namespace mls::log {

std::shared_ptr<Sink> Log::sink = nullptr;

void
Log::set_sink(std::shared_ptr<Sink> sink_in)
{
  sink = std::move(sink_in);
}

void
Log::remove_sink()
{
  sink = nullptr;
}

} // namespace mls::log
