#pragma once

#include <optional>
#include <string>
#include <unordered_set>

namespace ATK::SSL {
struct AllOutStrippingOptions {
    std::string ifaceIpOrName;
    std::optional<std::string> attackerMac;
};

void allOutStrip(const AllOutStrippingOptions &options);

struct SilentStrippingOptions {
    std::string ifaceIpOrName;
    std::optional<std::string> attackerMac;
    std::unordered_set<std::string> victimIps;
    std::unordered_set<std::string> domainsToSpoof;
};

void silentStrip(const SilentStrippingOptions &options);
} // namespace ATK::SSL
