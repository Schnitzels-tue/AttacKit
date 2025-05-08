#pragma once

#include "common/common.h"
#include <vector>

namespace ATK {
class Scout {
  public:
    static std::vector<ATK::Common::DeviceInfo> getDevices();

  private:
};
} // namespace ATK
