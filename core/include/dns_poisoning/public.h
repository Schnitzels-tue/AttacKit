#pragma once

#include <string>
#include <unordered_set>
namespace ATK::DNS {
struct AllOutPoisonOptions {
    std::string ifaceIpOrName; // network interface e.g. en0
    std::string victimIp;      // the IP of the DNS server to poison
    std::string attackerIp;    // the IP to reroute domains to
    std::unordered_set<std::string> domainsToSpoof; // domains to reroute
};

void allOutPoison(const AllOutPoisonOptions &options);
} // namespace ATK::DNS