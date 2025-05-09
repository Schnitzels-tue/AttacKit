#pragma once

#include "Packet.h"
#include "PcapLiveDevice.h"
#include "common/common.h"

namespace ATK::Common {
/**
 * Converts a pcap packet to a Common PacketInfo
 */
ATK::Common::PacketInfo toPacketInfo(const pcpp::Packet &packet);

/**
 * Converts a pcap device to a Common Interface device
 */
ATK::Common::InterfaceInfo toInterfaceInfo(const pcpp::PcapLiveDevice &device);
} // namespace ATK::Common
