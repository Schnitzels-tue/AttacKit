#pragma once

#include <optional>
#include <string>
#include <unordered_set>

namespace ATK::SSL {
enum MitmStrategy {
    ARP,
    DNS
};

struct AllOutStrippingOptions {
    std::string ifaceIpOrName;
    MitmStrategy mitmStrategy;
};

void allOutStrip(const AllOutStrippingOptions &options);

struct SilentStrippingOptions {
    std::string ifaceIpOrName;
    std::unordered_set<std::string> victimIps;
    std::unordered_set<std::string> domainsToStrip;
    std::optional<MitmStrategy> mitmStrategy;
};

void silentStrip(const SilentStrippingOptions &options);
} // namespace ATK::SSL
