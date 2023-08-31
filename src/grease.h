#pragma once

#include "mls/core_types.h"
#include <namespace.h>

namespace MLS_NAMESPACE {

Capabilities
grease(Capabilities&& capabilities, const ExtensionList& extensions);

ExtensionList
grease(ExtensionList&& extensions);

} // namespace MLS_NAMESPACE
