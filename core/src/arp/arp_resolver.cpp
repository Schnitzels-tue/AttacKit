#include "arp/arp_resolver.h"
#include "ArpLayer.h"
#include "EthLayer.h"
#include "IpAddress.h"
#include "MacAddress.h"
#include "Packet.h"
#include "PcapFilter.h"
#include "PcapLiveDevice.h"
#include "ProtocolType.h"
#include "RawPacket.h"
#include <future>
#include <stdexcept>

namespace {

constexpr int PACKET_SIZE = 60;

struct Packetinfo {
    pcpp::IPv4Address sourceIp;
    pcpp::IPv4Address targetIp;
    pcpp::MacAddress sourceMac;
};

pcpp::Packet createPacket(const Packetinfo &info) {

    pcpp::EthLayer ethLayer(info.sourceMac,
                            pcpp::MacAddress("ff:ff:ff:ff:ff:ff"),
                            PCPP_ETHERTYPE_ARP);

    pcpp::ArpLayer arpLayer(pcpp::ARP_REQUEST, info.sourceMac,
                            pcpp::MacAddress("00:00:00:00:00:00"),
                            info.sourceIp, info.targetIp);

    pcpp::Packet arpRequest(PACKET_SIZE);
    arpRequest.addLayer(&ethLayer);
    arpRequest.addLayer(&arpLayer);
    arpRequest.computeCalculateFields();

    return arpRequest;
}

struct PacketArrivalCookie {
    std::promise<pcpp::MacAddress> *macPromise{};
    pcpp::IPv4Address requestedIp;
    bool canceled{};
};

/**
 * If arp request never resolves this function never resolves
 *
 * @param cookie void* = promise*
 */
void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *device,
                     void *cookie) {
    auto *packetArrivalCookie = static_cast<PacketArrivalCookie *>(cookie);
    pcpp::Packet parsedPacket(packet);

    auto *arpLayer = parsedPacket.getLayerOfType<pcpp::ArpLayer>();
    if (arpLayer == nullptr) {
        return;
    }

    if (arpLayer->getSenderIpAddr() == packetArrivalCookie->requestedIp) {
        packetArrivalCookie->macPromise->set_value(
            arpLayer->getSenderMacAddress());
        device->stopCapture();
    }
}

} // namespace

pcpp::MacAddress ATK::ARP::resolveArp(pcpp::IPv4Address targetIp,
                                      pcpp::PcapLiveDevice &device) {

    if (!device.open()) {
        throw std::runtime_error("unable to open inerface" + device.getName());
    }

    pcpp::IPv4Address sourceIp = device.getIPv4Address();

    pcpp::MacAddress sourceMac = device.getMacAddress();
    Packetinfo packetInfo{
        .sourceIp = sourceIp, .targetIp = targetIp, .sourceMac = sourceMac};

    pcpp::Packet packet = createPacket(packetInfo);

    // set filters
    pcpp::ProtoFilter protoFilter(pcpp::ARP);
    pcpp::AndFilter andfilter;
    andfilter.addFilter(&protoFilter);
    if (!device.setFilter(andfilter)) {
        throw std::runtime_error("Failed to set BRP filter");
    };

    std::promise<pcpp::MacAddress> promise;
    std::future<pcpp::MacAddress> future = promise.get_future();
    bool canceled = false;
    PacketArrivalCookie cookie{&promise, targetIp, false};

    device.sendPacket(&packet);

    device.startCapture(onPacketArrives, &promise);

    return future.get();
}
