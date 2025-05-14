#pragma once

#include "PcapLiveDevice.h"
#include "arp_poisoning/arp_poisoning_strategy.h"

namespace ATK::ARP {
/**
 * Silent ARP poisoning attack.
 *
 * Will try to spoof only a single ip address.
 */
class SilentArpPoisoningStrategy : public ATK::ARP::ArpPoisoningStrategy {
  public:
    class Builder {
      public:
        Builder(pcpp::PcapLiveDevice *device, pcpp::IPv4Address ipToSpoof)
            : device_(device), ipToSpoof_(ipToSpoof) {}
        /**
         * If no victimIp is supplied, it will respond to all sources.
         */
        Builder &victimIp(pcpp::IPv4Address victimIp) {
            victimIp_ = victimIp;
            return *this;
        }
        Builder &attackerMac(pcpp::MacAddress attackerMac) {
            attackerMac_ = attackerMac;
            return *this;
        }

        /**
         * If no attackerMac is supplied it will default to the mac adress of
         * the interface.
         */
        std::unique_ptr<SilentArpPoisoningStrategy> build() {
            return std::unique_ptr<SilentArpPoisoningStrategy>(
                new SilentArpPoisoningStrategy(this->device_, this->victimIp_,
                                               this->attackerMac_,
                                               this->ipToSpoof_));
        }

      private:
        pcpp::PcapLiveDevice *device_;
        std::optional<pcpp::IPv4Address> victimIp_;
        std::optional<pcpp::MacAddress> attackerMac_;
        pcpp::IPv4Address ipToSpoof_;
    };

    /**
     * Executes silent arp poisoning attack.
     *
     * Replies to incoming arp requests for the ip address ipToSpoof.
     * If victimIp is set, it will only reply to arp requests to the victim.
     * When no attackerMac
     *
     */
    void execute() override;

  private:
    SilentArpPoisoningStrategy(pcpp::PcapLiveDevice *device,
                               std::optional<pcpp::IPv4Address> victimIp,
                               std::optional<pcpp::MacAddress> attackerMac,
                               pcpp::IPv4Address ipToSpoof)
        : device_(device), victimIp_(victimIp), ipToSpoof_(ipToSpoof) {
        if (device == nullptr) {
            throw std::invalid_argument("Not a valid interface");
        }

        attackerMac_ = attackerMac.value_or(device->getMacAddress());
    }

    void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device,
                         void *cookie);

    pcpp::PcapLiveDevice *device_;
    std::optional<pcpp::IPv4Address> victimIp_;
    pcpp::MacAddress attackerMac_;
    pcpp::IPv4Address ipToSpoof_;
};
} // namespace ATK::ARP
