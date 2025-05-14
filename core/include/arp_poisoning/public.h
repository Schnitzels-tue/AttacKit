#pragma once

#include <optional>
#include <string>

namespace ATK::ARP {
struct AllOutPoisoningOptions {
    std::string ifaceIpOrName;
    std::optional<std::string> attackerMac;
};

void allOutPoison(const AllOutPoisoningOptions &options);

struct SilentPoisoningOptions {
    std::string ifaceIpOrName;
    std::optional<std::string> attackerMac;
    std::optional<std::string> victimIp;
    std::string ipToSpoof;
};

void silentPoison(const SilentPoisoningOptions &options);
} // namespace ATK::ARP
