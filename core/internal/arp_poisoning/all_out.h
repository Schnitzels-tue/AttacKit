#include "MacAddress.h"
#include "PcapLiveDevice.h"
#include "arp_poisoning/arp_poisoning_strategy.h"
#include <memory>
#include <stdexcept>

namespace ATK::ARP {
class AllOutArpPoisoningStrategy : public ATK::ARP::ArpPoisoningStrategy {
  public:
    class Builder {
      public:
        explicit Builder(pcpp::PcapLiveDevice *device) : device_(device) {}
        Builder &attackerMac(pcpp::MacAddress attackerMac) {
            this->attackerMac_ = attackerMac;
            return *this;
        }
        std::unique_ptr<AllOutArpPoisoningStrategy> build() {
            return std::unique_ptr<AllOutArpPoisoningStrategy>(
                new AllOutArpPoisoningStrategy(this->device_,
                                               this->attackerMac_));
        }

      private:
        pcpp::PcapLiveDevice *device_;
        std::optional<pcpp::MacAddress> attackerMac_;
    };

    void execute() override;

  private:
    AllOutArpPoisoningStrategy(pcpp::PcapLiveDevice *device,
                               std::optional<pcpp::MacAddress> attackerMac) {
        if (device == nullptr) {
            throw std::invalid_argument("Not a valid interface");
        }

        device_ = device;
        attackerMac_ = attackerMac.value_or(device->getMacAddress());
    }
    pcpp::PcapLiveDevice *device_;
    pcpp::MacAddress attackerMac_;
};
} // namespace ATK::ARP
