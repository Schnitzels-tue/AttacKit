#include "arp_poisoning/silent.h"
#include <stdexcept>

void ATK::ARP::SilentArpPoisoningStrategy::onPacketArrives(
    pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) {}

void ATK::ARP::SilentArpPoisoningStrategy::execute() {
    if (!device_->open()) {
        throw std::runtime_error("Unable to open interface");
    }

    device_->close();
}
