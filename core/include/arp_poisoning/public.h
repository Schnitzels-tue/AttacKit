#pragma once

#include <optional>
#include <string>
#include <unordered_set>

namespace ATK::ARP {
struct AllOutPoisoningOptions {
    std::string ifaceIpOrName;
    std::optional<std::string> attackerMac;
};

void allOutPoison(const AllOutPoisoningOptions &options);

struct SilentPoisoningOptions {
    std::string ifaceIpOrName;
    std::optional<std::string> attackerMac;
    std::unordered_set<std::string> victimIps;
    std::unordered_set<std::string> ipsToSpoof;
};

void silentPoison(const SilentPoisoningOptions &options);
} // namespace ATK::ARP
