#pragma once

#include <string>
namespace ATK::DNS {
struct AllOutPoisonOptions {
    std::string ifaceIpOrName; //network interface e.g. en0
    std::string attackerIp;
};

void allOutPoison(const AllOutPoisonOptions &options);
} // namespace ATK::DNS