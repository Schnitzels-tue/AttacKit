#pragma once

#include <optional>
#include <string>
#include <unordered_set>

namespace ATK::SSL {
enum MitmStrategy { ARP, DNS };

struct AllOutStrippingOptions {
    std::string ifaceIpOrName;
    std::optional<std::string> attackerIp; // Only when using DNS
    MitmStrategy mitmStrategy;
};

void allOutStrip(const AllOutStrippingOptions &options);

struct SilentStrippingOptions {
    std::string ifaceIpOrName;
    std::optional<std::string> attackerIp; // Only when using DNS
    std::unordered_set<std::string> victimIps;
    std::unordered_set<std::string> domainsToStrip;
    MitmStrategy mitmStrategy;
};

void silentStrip(const SilentStrippingOptions &options);
} // namespace ATK::SSL
