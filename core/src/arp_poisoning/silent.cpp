#include "arp_poisoning/silent.h"
#include "ArpLayer.h"
#include "EthLayer.h"
#include "PcapFilter.h"
#include "PcapLiveDevice.h"
#include "RawPacket.h"
#include <future>
#include <stdexcept>

void ATK::ARP::SilentArpPoisoningStrategy::onPacketArrives(
    pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) {}

void ATK::ARP::SilentArpPoisoningStrategy::execute() {
    if (!device_->open()) {
        throw std::runtime_error("Unable to open interface");
    }

    std::promise<void> completionPromise;
    std::future<void> completionFuture = completionPromise.get_future();

    // set filters
    pcpp::ArpFilter arpFilter(pcpp::ArpOpcode::ARP_REQUEST);
    pcpp::EtherTypeFilter etherTypeFilter(PCPP_ETHERTYPE_ARP);
    pcpp::AndFilter andFilter;
    andFilter.addFilter(&arpFilter);
    andFilter.addFilter(&etherTypeFilter);

    device_->setFilter(andFilter);

    device_->startCapture(
        [this](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device,
               void *cookie) { onPacketArrives(packet, device, cookie); },
        &completionFuture);

    completionFuture.wait();

    device_->close();
}
