#pragma once

#include "MacAddress.h"
#include "PcapLiveDevice.h"
#include "RawPacket.h"
#include "dns_poisoning/dns_poisoning_strategy.h"
#include <memory>
#include <optional>
#include <stdexcept>

namespace ATK::DNS {
/**
 * All out DNS poisoning strategy, will capture every DNS request packet except
 * the attacker's and send back the attackerMac.
 */
class AllOutDnsPoisoningStrategy : public ATK::DNS::DnsPoisoningStrategy {
  public:
    class Builder {
      public:
        explicit Builder(pcpp::PcapLiveDevice *device) : device_(device) {}
        Builder &attackerMac(pcpp::MacAddress attackerMac) {
            this->attackerMac_ = std::optional<pcpp::MacAddress>(attackerMac);
            return *this;
        }
        /**
         * If no attackerMac is supplied, default to the mac address of the
         * interface
         */
        std::unique_ptr<AllOutDnsPoisoningStrategy> build() {
            return std::unique_ptr<AllOutDnsPoisoningStrategy>(
                new AllOutDnsPoisoningStrategy(this->device_,
                                               this->attackerMac_));
        }

      private:
        pcpp::PcapLiveDevice *device_;
        std::optional<pcpp::MacAddress> attackerMac_;
    };

    /**
     * Executes Arp all out poisoning attack.
     *
     * Will reply to every incoming DNS packet, except those to the attacker's
     * interface with the attackerMac.
     */
    void execute() override;

  private:
    AllOutDnsPoisoningStrategy(pcpp::PcapLiveDevice *device,
                               std::optional<pcpp::MacAddress> attackerMac)
        : device_(device) {
        if (device == nullptr) {
            throw std::invalid_argument("Not a valid interface");
        }

        attackerMac_ = attackerMac.value_or(device->getMacAddress());
    }

    void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device,
                         void *cookie) override;

    pcpp::PcapLiveDevice *device_;
    pcpp::MacAddress attackerMac_;
};
} // namespace ATK::DNS
