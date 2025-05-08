#include "network_scout/network_scout.h"
#include "EthLayer.h"
#include "Packet.h"
#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"
#include "RawPacket.h"

#include <iostream>
#include <stdexcept>
#include <vector>

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

    pcpp::Packet parsedPacket(packet);
    ATK::Common::PacketInfo packetInfo{
        parsedPacket.getLayerOfType<pcpp::EthLayer>()->toString()};

    packetTracker->packetInfoList->emplace_back(packetInfo);
    packetTracker->packetsToCapture--;

    // return false means we don't want to stop capturing after this
    // callback
    return packetTracker->packetsToCapture <= 0;
}
} // namespace

std::vector<ATK::Common::DeviceInfo> ATK::Scout::getInterfaces() {
    auto devices =
        pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

    std::vector<ATK::Common::DeviceInfo> deviceInfoList;
    deviceInfoList.reserve(devices.size());

    for (auto *device : devices) {
        ATK::Common::DeviceInfo DeviceInfo{
            .name = device->getName(),
            .iPv4Adress = device->getIPv4Address().toString(),
            .iPv6Adress = device->getIPv6Address().toString(),
            .macAdress = device->getMacAddress().toString(),
            .active = device->captureActive()};

        deviceInfoList.emplace_back(DeviceInfo);
    }

    return deviceInfoList;
}

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

    std::cout << packetInfoList.size();
    device->close();

    return packetInfoList;
}
