#pragma once

#include "mls/core_types.h"

namespace mls {

Capabilities
grease(Capabilities&& capabilities, const ExtensionList& extensions);

ExtensionList
grease(ExtensionList&& extensions);

} // namespace mls
