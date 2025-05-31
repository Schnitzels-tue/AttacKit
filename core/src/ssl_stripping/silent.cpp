#include "ssl_stripping/silent.h"
#include "HttpLayer.h"
#include "IPv4Layer.h"
#include "IpAddress.h"
#include "Packet.h"
#include "PcapFilter.h"
#include "PcapLiveDevice.h"
#include "RawPacket.h"
#include "TcpLayer.h"
#include "log.h"
#include <algorithm>
#include <exception>
#include <future>
#include <stdexcept>
#include <vector>

void ATK::SSL::SilentSslStrippingStrategy::onPacketArrives(
    pcpp::RawPacket *packet, pcpp::PcapLiveDevice * /*device*/,
    void * /*cookie*/) {
    pcpp::Packet parsedPacket(packet);

    // Check IPv4 layer
    auto *ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    if (ipLayer == nullptr) {
        return;
    }

    // Check if destination IP matches some victim IP
    if (std::find(victimIps_.begin(), victimIps_.end(),
                  ipLayer->getDstIPAddress().toString()) == victimIps_.end()) {
        return;
    }

    // Check TCP layer
    auto *tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
    const int HTTP_PORT = 80;
    if ((tcpLayer == nullptr) || tcpLayer->getDstPort() != HTTP_PORT) {
        return;
    }

    // Access HTTP Layer
    auto *httpRequestLayer =
        parsedPacket.getLayerOfType<pcpp::HttpRequestLayer>();
    if (httpRequestLayer == nullptr) {
        return;
    }

    // Check if method is GET
    if (httpRequestLayer->getFirstLine()->getMethod() !=
        pcpp::HttpRequestLayer::HttpGET) {
        return;
    }

    // Check Host header
    pcpp::HeaderField *hostField = httpRequestLayer->getFieldByName("Host");
    if (hostField == nullptr) {
        return;
    }

    // Check whether domain is in Host header and start SSL attack if so
    std::string hostValue = hostField->getFieldValue();
    for (const std::string &domain : domainsToStrip_) {
        if (hostValue.find(domain) != std::string::npos) {
            // TODO(Quinn)
        }
    }
}

void ATK::SSL::SilentSslStrippingStrategy::execute() {
    if (!device_->open()) {
        throw std::runtime_error("Unable to open interface");
    }

    std::promise<void> completionPromise;
    std::future<void> completionFuture = completionPromise.get_future();

    if (!device_->setFilter("tcp dst port 80")) {
        LOG_ERROR("Cannot set tcp filter");
        device_->close();
        throw std::runtime_error(
            "Unable to set http request filters on interface");
    };

    if (!device_->startCapture(
            [this](pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device,
                   void *cookie) { onPacketArrives(packet, device, cookie); },
            &completionFuture)) {
        device_->close();
        throw std::runtime_error("Unable to start capturing http packets");
    };

    try {
        completionFuture.get();
    } catch (const std::exception &e) {
        device_->close();
    }

    device_->close();
}
