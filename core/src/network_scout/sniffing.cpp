#include "network_scout/sniffing.h"
#include "PcapLiveDeviceList.h"
#include "common/pcap_to_common.h"

namespace {
constexpr int MAX_CAPTURE_TIMEOUT = 10;

/**
 * Tracks the progress of packet capture
 */
struct PacketTracker {
    int packetsToCapture; // how many more packets to capture.
    std::vector<ATK::Common::PacketInfo> *packetInfoList;
};

/**
 * Caputure N packets
 *
 */
bool onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice * /*dev*/,
                     void *cookie) {

    auto *packetTracker = static_cast<PacketTracker *>(cookie);
    const pcpp::Packet parsedPacket(packet);

    packetTracker->packetInfoList->emplace_back(
        ATK::Common::toPacketInfo(parsedPacket));
    packetTracker->packetsToCapture--;

    // return false means we don't want to stop capturing after this
    // callback
    return packetTracker->packetsToCapture <= 0;
}
} // namespace

std::vector<ATK::Common::PacketInfo>
ATK::Scout::sniffPackets(const std::string &deviceIpOrName, int numPackets) {
    std::vector<ATK::Common::PacketInfo> packetInfoList;
    packetInfoList.reserve(numPackets);

    pcpp::PcapLiveDevice *device =
        pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(
            deviceIpOrName);

    if (device == nullptr || !device->open()) {
        throw std::invalid_argument("Unable to open device: " + deviceIpOrName);
    }

    PacketTracker tracker{.packetsToCapture = numPackets,
                          .packetInfoList = &packetInfoList};
    device->startCaptureBlockingMode(onPacketArrives, &tracker,
                                     MAX_CAPTURE_TIMEOUT);

    device->close();

    return packetInfoList;
}
