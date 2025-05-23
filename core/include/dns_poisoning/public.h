#pragma once

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
    std::unordered_set<std::string>
        domainsToSpoof; // domains to spoof (empty equates to any)
};

void silentPoison(const SilentPoisoningOptions &options);
} // namespace ATK::DNS