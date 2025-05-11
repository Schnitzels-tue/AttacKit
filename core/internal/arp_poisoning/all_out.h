#include "MacAddress.h"
#include "PcapLiveDevice.h"
#include "arp_poisoning/arp_poisoning_strategy.h"
#include <stdexcept>

namespace ATK::ARP {
class AllOutArpPoisoningStrategy : public ATK::ARP::ArpPoisoningStrategy {
  public:
    AllOutArpPoisoningStrategy(pcpp::PcapLiveDevice *device,
                               pcpp::MacAddress attackerMacAddress) {
        if (device == nullptr) {
            throw std::invalid_argument("Not a valid interface");
        }

        device_ = device;
        attackerMacAddress_ = attackerMacAddress;
    }

    explicit AllOutArpPoisoningStrategy(pcpp::PcapLiveDevice *device) {
        if (device == nullptr) {
            throw std::invalid_argument("Not a valid interface");
        }

        device_ = device;
        attackerMacAddress_ = device->getMacAddress();
    }

    void execute() override;

  private:
    pcpp::PcapLiveDevice *device_;
    pcpp::MacAddress attackerMacAddress_;
};
} // namespace ATK::ARP
