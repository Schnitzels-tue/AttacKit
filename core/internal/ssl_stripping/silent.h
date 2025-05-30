#pragma once

#include "IpAddress.h"
#include "PcapLiveDevice.h"
#include "ssl_stripping/ssl_stripping_strategy.h"
#include <optional>
#include <utility>

namespace ATK::SSL {
/**
 * Silent ssl stripping attack.
 *
 * Will try to only ssl strip for certain IPs and certain domains
 */
class SilentSslStrippingStrategy : public ATK::SSL::SslStrippingStrategy {
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
        Builder &addDomainToSpoof(std::string domainToSpoof) {
            domainsToSpoof_.emplace_back(domainToSpoof);
            return *this;
        }

        /**
         * If no attackerMac is supplied it will default to the mac adress of
         * the interface.
         */
        std::unique_ptr<SilentSslStrippingStrategy> build() {
            return std::unique_ptr<SilentSslStrippingStrategy>(
                new SilentSslStrippingStrategy(this->device_, this->victimIps_,
                                               this->domainsToSpoof_));
        }

      private:
        pcpp::PcapLiveDevice *device_;
        std::vector<pcpp::IPv4Address> victimIps_;
        std::optional<pcpp::MacAddress> attackerMac_;
        std::vector<std::string> domainsToSpoof_;
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
    SilentSslStrippingStrategy(pcpp::PcapLiveDevice *device,
                               std::vector<pcpp::IPv4Address> victimIps,
                               std::vector<std::string> domainsToSpoof)
        : device_(device), victimIps_(std::move(victimIps)),
          domainsToSpoof_(std::move(domainsToSpoof)) {
        if (device == nullptr) {
            throw std::invalid_argument("Not a valid interface");
        }
    }

    void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device,
                         void *cookie);

    pcpp::PcapLiveDevice *device_;
    std::vector<pcpp::IPv4Address> victimIps_;
    std::vector<std::string> domainsToSpoof_;
};
} // namespace ATK::SSL
