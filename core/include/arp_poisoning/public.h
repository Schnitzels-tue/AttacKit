#pragma once

#include <string>
namespace ATK::ARP {
struct AllOutPoisonOptions {
    std::string ifaceIpOrName;
    std::string attackerMacAddress;
};

void allOutPoison(const AllOutPoisonOptions &options);
} // namespace ATK::ARP
