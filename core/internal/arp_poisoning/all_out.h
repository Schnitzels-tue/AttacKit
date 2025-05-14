#pragma once

#include "PcapLiveDevice.h"
#include "arp_poisoning/arp_poisoning_strategy.h"

namespace ATK::ARP {
/**
 * All out arp poisoning strategy, will capture every arp request packet except
 * the attacker's and send back the attackerMac.
 */
class AllOutArpPoisoningStrategy : public ATK::ARP::ArpPoisoningStrategy {
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
        std::unique_ptr<AllOutArpPoisoningStrategy> build() {
            return std::unique_ptr<AllOutArpPoisoningStrategy>(
                new AllOutArpPoisoningStrategy(this->device_,
                                               this->attackerMac_));
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
    AllOutArpPoisoningStrategy(pcpp::PcapLiveDevice *device,
                               std::optional<pcpp::MacAddress> attackerMac)
        : device_(device) {
        if (device == nullptr) {
            throw std::invalid_argument("Not a valid interface");
        }

        attackerMac_ = attackerMac.value_or(device->getMacAddress());
    }

    void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device,
                         void *cookie);

    pcpp::PcapLiveDevice *device_;
    pcpp::MacAddress attackerMac_;
};
} // namespace ATK::ARP
