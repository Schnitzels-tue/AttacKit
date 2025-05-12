#include "arp_poisoning/silent.h"
#include "EthLayer.h"
#include "IpAddress.h"
#include <future>
#include <stdexcept>

namespace {
struct SilentArpPoisoningCookie {
    pcpp::MacAddress attackerMac;
    std::optional<pcpp::IPv4Address> victimIp;
    pcpp::IPv4Address ipToSpoof;
    std::promise<void> completionPromise;
};

} // namespace

void ATK::ARP::SilentArpPoisoningStrategy::onPacketArrives(
    pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) {}

void ATK::ARP::SilentArpPoisoningStrategy::execute() {
    if (!device_->open()) {
        throw std::runtime_error("Unable to open interface");
    }

    device_->close();
}
