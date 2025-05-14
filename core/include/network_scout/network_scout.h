#pragma once

#include "common/common.h"

namespace ATK::Scout {

/**
 * Gets the list of interfaces available and returns their information.
 */
std::vector<ATK::Common::InterfaceInfo> getInterfaces();
} // namespace ATK::Scout
