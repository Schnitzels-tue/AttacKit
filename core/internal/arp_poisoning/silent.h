#include "IpAddress.h"
#include "MacAddress.h"
#include "PcapLiveDevice.h"
#include "arp_poisoning/arp_poisoning_strategy.h"
#include <optional>
#include <stdexcept>

namespace ATK::ARP {
class SilentArpPoisoningStrategy : public ATK::ARP::ArpPoisoningStrategy {
  public:
    SilentArpPoisoningStrategy(pcpp::PcapLiveDevice *device,
                               pcpp::IPv4Address victimIp,
                               pcpp::MacAddress attackerMac,
                               pcpp::IPv4Address ipToSpoof) {
        if (device == nullptr) {
            throw std::invalid_argument("Not a valid interface");
        }

        device_ = device;
        victimIp_ = std::optional<pcpp::IPv4Address>(victimIp);
        attackerMac_ = attackerMac;
        ipToSpoof_ = ipToSpoof;
    }

    SilentArpPoisoningStrategy(pcpp::PcapLiveDevice *device,
                               pcpp::MacAddress attackerMac,
                               pcpp::IPv4Address ipToSpoof) {
        if (device == nullptr) {
            throw std::invalid_argument("Not a valid interface");
        }

        device_ = device;
        attackerMac_ = attackerMac;
        victimIp_ = std::nullopt;
        ipToSpoof_ = ipToSpoof;
    }

    SilentArpPoisoningStrategy(pcpp::PcapLiveDevice *device,
                               pcpp::IPv4Address victimIp,
                               pcpp::IPv4Address ipToSpoof) {
        if (device == nullptr) {
            throw std::invalid_argument("Not a valid interface");
        }

        device_ = device;
        attackerMac_ = std::nullopt;
        victimIp_ = std::optional<pcpp::IPv4Address>(victimIp);
        ipToSpoof_ = ipToSpoof;
    }

    SilentArpPoisoningStrategy(pcpp::PcapLiveDevice *device,
                               pcpp::IPv4Address ipToSpoof) {
        if (device == nullptr) {
            throw std::invalid_argument("Not a valid interface");
        }

        device_ = device;
        attackerMac_ = std::nullopt;
        victimIp_ = std::nullopt;
        ipToSpoof_ = ipToSpoof;
    }

    void execute() override;

  private:
    pcpp::PcapLiveDevice *device_;
    // optional if you want to target any request
    std::optional<pcpp::IPv4Address> victimIp_;
    std::optional<pcpp::MacAddress> attackerMac_;
    pcpp::IPv4Address ipToSpoof_;
};
} // namespace ATK::ARP
