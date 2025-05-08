#pragma once

#include <string>
#include <vector>

namespace Scout {
struct DeviceInfo {
    std::string name;
    std::string iPv4Adress;
    std::string iPv6Adress;
    std::string macAdress;
    std::string description;
    bool active;
};
std::vector<DeviceInfo> getDevices();
} // namespace Scout
