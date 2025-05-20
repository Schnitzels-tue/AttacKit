#pragma once

#include "IpAddress.h"
#include "PcapLiveDevice.h"
#include "arp_poisoning/arp_poisoning_strategy.h"
#include <optional>
#include <utility>

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
        explicit Builder(pcpp::PcapLiveDevice *device) : device_(device) {}
        /**
         * Adds a victim
         */
        Builder &addVictimIp(pcpp::IPv4Address victimIp) {
            victimIps_.emplace_back(victimIp);
            return *this;
        }
        Builder &addIpToSpoof(pcpp::IPv4Address ipToSpoof) {
            ipsToSpoof_.emplace_back(ipToSpoof);
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
                new SilentArpPoisoningStrategy(this->device_, this->victimIps_,
                                               this->attackerMac_,
                                               this->ipsToSpoof_));
        }

      private:
        pcpp::PcapLiveDevice *device_;
        std::vector<pcpp::IPv4Address> victimIps_;
        std::optional<pcpp::MacAddress> attackerMac_;
        std::vector<pcpp::IPv4Address> ipsToSpoof_;
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
                               std::vector<pcpp::IPv4Address> victimIps,
                               std::optional<pcpp::MacAddress> attackerMac,
                               std::vector<pcpp::IPv4Address> ipsToSpoof)
        : device_(device), victimIps_(std::move(victimIps)),
          ipsToSpoof_(std::move(ipsToSpoof)) {
        if (device == nullptr) {
            throw std::invalid_argument("Not a valid interface");
        }

        attackerMac_ = attackerMac.value_or(device->getMacAddress());
    }

    void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device,
                         void *cookie);

    pcpp::PcapLiveDevice *device_;
    std::vector<pcpp::IPv4Address> victimIps_;
    pcpp::MacAddress attackerMac_;
    std::vector<pcpp::IPv4Address> ipsToSpoof_;
};
} // namespace ATK::ARP
