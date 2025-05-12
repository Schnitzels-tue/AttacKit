#pragma once

#include "IpAddress.h"
#include "MacAddress.h"
#include "PcapLiveDevice.h"
#include "arp_poisoning/arp_poisoning_strategy.h"
#include <memory>
#include <optional>
#include <stdexcept>

namespace ATK::ARP {
class SilentArpPoisoningStrategy : public ATK::ARP::ArpPoisoningStrategy {
  public:
    class Builder {
        Builder(pcpp::PcapLiveDevice *device, pcpp::IPv4Address ipToSpoof)
            : device_(device), ipToSpoof_(ipToSpoof) {}
        Builder &victimIp(pcpp::IPv4Address victimIp) {
            victimIp_ = victimIp;
            return *this;
        }
        Builder &attackerMac(pcpp::MacAddress attackerMac) {
            attackerMac_ = attackerMac;
            return *this;
        }
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
    pcpp::PcapLiveDevice *device_;
    std::optional<pcpp::IPv4Address> victimIp_;
    pcpp::MacAddress attackerMac_;
    pcpp::IPv4Address ipToSpoof_;
};
} // namespace ATK::ARP
