#pragma once

#include "IpAddress.h"
#include "MacAddress.h"
#include "PcapLiveDevice.h"
namespace ATK::ARP {
/**
 * Get the MAC Adress of an ip
 *
 * @throws invalid_argument if not a valid ip
 * @throws runtime_error if unable to open interface
 * @throws runtime_error if unable to set BRP filter for ARP packets
 */
pcpp::MacAddress resolveArp(pcpp::IPv4Address targetIp,
                            pcpp::PcapLiveDevice &device);
} // namespace ATK::ARP
