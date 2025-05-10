#pragma once

#include "IpAddress.h"
#include "MacAddress.h"
#include "PcapLiveDevice.h"
#include <chrono>
namespace ATK::ARP {
constexpr int ARP_PING_ATTEMPTS = 10;
constexpr std::chrono::duration ARP_TIMEOUT_DURATION =
    std::chrono::milliseconds(4000);
constexpr int PACKET_SIZE = 60;
/**
 * Get the MAC Address of an ip
 *
 * @throws invalid_argument if not a valid ip
 * @throws runtime_error if unable to open interface
 * @throws runtime_error if unable to set BRP filter for ARP packets
 */
pcpp::MacAddress resolveArp(pcpp::IPv4Address targetIp,
                            pcpp::PcapLiveDevice &device);
} // namespace ATK::ARP
