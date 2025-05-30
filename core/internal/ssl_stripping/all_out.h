#pragma once

#include "PcapLiveDevice.h"
#include "ssl_stripping/ssl_stripping_strategy.h"
#include <optional>

namespace ATK::SSL {
/**
 * All out ssl stripping strategy, will capture every http get request packet except
 * the attacker's and send back an unencrypted connection imitating a connection 
 * to the server the victim was trying to connect to.
 */
class AllOutSslStrippingStrategy : public ATK::SSL::SslStrippingStrategy {
  public:
    class Builder {
      public:
        explicit Builder(pcpp::PcapLiveDevice *device) : device_(device) {}
        std::unique_ptr<AllOutSslStrippingStrategy> build() {
            return std::unique_ptr<AllOutSslStrippingStrategy>(
                new AllOutSslStrippingStrategy(this->device_));
        }

      private:
        pcpp::PcapLiveDevice *device_;
        std::optional<pcpp::MacAddress> attackerMac_;
    };

    /**
     * Executes Arp all out poisoning attack.
     *
     * Will reply to every incoming ARP packet, except those to the attacker's
     * interface with the attackerMac.
     */
    void execute() override;

  private:
    explicit AllOutSslStrippingStrategy(pcpp::PcapLiveDevice *device)
        : device_(device) {
        if (device == nullptr) {
            throw std::invalid_argument("Not a valid interface");
        }
    }

    void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device,
                         void *cookie);

    pcpp::PcapLiveDevice *device_;
};
} // namespace ATK::SSL
