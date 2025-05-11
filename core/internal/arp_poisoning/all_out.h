#include "MacAddress.h"
#include "PcapLiveDevice.h"
#include "arp_poisoning/arp_poisoning_strategy.h"
namespace ATK::ARP {
class AllOutArpPoisoningStrategy : public ATK::ARP::ArpPoisoningStrategy {
  public:
    AllOutArpPoisoningStrategy(pcpp::PcapLiveDevice *device,
                               pcpp::MacAddress attackerMacAddress)
        : device_(device), attackerMacAddress_(attackerMacAddress) {}

    explicit AllOutArpPoisoningStrategy(pcpp::PcapLiveDevice *device)
        : device_(device) {
        attackerMacAddress_ = device_->getMacAddress();
    }
    void execute() override;

  private:
    pcpp::PcapLiveDevice *device_;
    pcpp::MacAddress attackerMacAddress_;
};
} // namespace ATK::ARP
