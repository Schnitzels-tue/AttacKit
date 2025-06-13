#pragma once

#include "IpAddress.h"
#include "PcapLiveDevice.h"
#include "ssl_stripping/public.h"
#include "ssl_stripping/ssl_stripping_strategy.h"
#include <condition_variable>
#include <mutex>
#include <queue>
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
        /**
         * Adds an attacker IP
         */
        Builder &addAttackerIp(pcpp::IPv4Address attackerIp) {
            attackerIp_ = attackerIp;
            return *this;
        }
        /**
         * Adds a domain to strip
         */
        Builder &addDomainToStrip(std::string domainToStrip) {
            domainsToStrip_.emplace_back(domainToStrip);
            return *this;
        }
        Builder &setMitmStrategy(ATK::SSL::MitmStrategy mitmStrategy) {
            mitmStrategy_ = mitmStrategy;
            return *this;
        }

        std::unique_ptr<SilentSslStrippingStrategy> build() {
            return std::unique_ptr<SilentSslStrippingStrategy>(
                new SilentSslStrippingStrategy(
                    this->device_, this->attackerIp_, this->victimIps_,
                    this->domainsToStrip_, this->mitmStrategy_));
        }

      private:
        pcpp::PcapLiveDevice *device_;
        pcpp::IPv4Address attackerIp_;
        std::vector<pcpp::IPv4Address> victimIps_;
        std::vector<std::string> domainsToStrip_;
        ATK::SSL::MitmStrategy mitmStrategy_{};
    };

    /**
     * Executes silent ssl stripping attack.
     *
     * Replies to incoming http requests from any victim IP in victimIps, for
     * any domain in domainsToStrip.
     *
     */
    void execute() override;

  private:
    // Function to get global variables safely
    struct HttpMessageData {
        std::queue<std::string> httpMessages;
        std::mutex httpMessagesMutex;
        std::condition_variable httpMessagesCV;
    };

    static HttpMessageData &getHttpMessageData() {
        static HttpMessageData data;
        return data;
    }

    SilentSslStrippingStrategy(pcpp::PcapLiveDevice *device,
                               pcpp::IPv4Address attackerIp,
                               std::vector<pcpp::IPv4Address> victimIps,
                               std::vector<std::string> domainsToStrip,
                               ATK::SSL::MitmStrategy mitmStrategy)
        : device_(device), attackerIp_(attackerIp),
          victimIps_(std::move(victimIps)),
          domainsToStrip_(std::move(domainsToStrip)),
          mitmStrategy_(mitmStrategy) {
        if (device == nullptr) {
            throw std::invalid_argument("Not a valid interface");
        }
    }

    void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device,
                         void *cookie);
    static std::optional<std::string>
    connectWithServer(const std::string &domain);

    static std::optional<std::unordered_set<std::string>>
    resolveDomainToIP(const std::string &domain, const std::string &service);

    static void runHttpDummyServer();

    pcpp::PcapLiveDevice *device_;
    pcpp::IPv4Address attackerIp_;
    std::vector<pcpp::IPv4Address> victimIps_;
    std::vector<std::string> domainsToStrip_;
    ATK::SSL::MitmStrategy mitmStrategy_;
};
} // namespace ATK::SSL
