#pragma once

#include <string>
#include <vector>

namespace ATK::Common {
struct InterfaceInfo {
    std::string name;
    std::string iPv4Adress;
    std::string iPv6Adress;
    std::string macAdress;
    std::string description;
};

/**
 * For now only has the string representation of each layer.
 * Lots of work to pattern match all the layers and parse them.
 */
struct PacketInfo {
    std::vector<std::string> info;
};
} // namespace ATK::Common
