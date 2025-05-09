#include "common/pcap_to_common.h"
#include "Layer.h"
#include "Packet.h"
#include "common/common.h"

ATK::Common::PacketInfo ATK::Common::toPacketInfo(const pcpp::Packet &packet) {
    ATK::Common::PacketInfo packetInfo{};

    packet.toStringList(packetInfo.info);

    return packetInfo;
}

ATK::Common::InterfaceInfo
ATK::Common::toInterfaceInfo(const pcpp::PcapLiveDevice &device) {
    return {.name = device.getName(),
            .iPv4Address = device.getIPv4Address().toString(),
            .iPv6Address = device.getIPv6Address().toString(),
            .macAddress = device.getMacAddress().toString(),
            .description = device.getDesc()};
}
