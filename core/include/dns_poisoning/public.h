#pragma once

#include <optional>
#include <string>
#include <unordered_set>

namespace ATK::DNS {
struct AllOutPoisoningOptions {
    std::string ifaceIpOrName; // network interface e.g. en0
    std::string attackerIp;    // the IP to reroute domains to
};

void allOutPoison(const AllOutPoisoningOptions &options);

struct SilentPoisoningOptions {
    std::string ifaceIpOrName; // network interface e.g. en0
    std::string victimIp;      // the IP of the DNS server to poison
    std::string attackerIp;    // the IP to reroute domains to

    // optionally provide only specific domains to be poisoned
    std::optional<std::unordered_set<std::string>> domainsToSpoof;
};

void silentPoison(const SilentPoisoningOptions &options);
} // namespace ATK::DNS