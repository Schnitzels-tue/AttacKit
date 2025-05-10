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
#include <exception>
#include <future>
#include <stdexcept>

namespace {

struct Packetinfo {
    pcpp::IPv4Address sourceIp;
    pcpp::IPv4Address targetIp;
    pcpp::MacAddress sourceMac;
};

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
            arpLayer->getTargetMacAddress());
    }
}

} // namespace

pcpp::MacAddress ATK::ARP::resolveArp(pcpp::IPv4Address targetIp,
                                      pcpp::PcapLiveDevice &device) {

    if (!device.open()) {
        throw std::runtime_error("unable to open interface" + device.getName());
    }

    pcpp::IPv4Address sourceIp = device.getIPv4Address();
    pcpp::MacAddress sourceMac = device.getMacAddress();

    pcpp::EthLayer ethLayer(sourceMac, pcpp::MacAddress("ff:ff:ff:ff:ff:ff"),
                            PCPP_ETHERTYPE_ARP);

    pcpp::ArpLayer arpLayer(pcpp::ARP_REQUEST, sourceMac,
                            pcpp::MacAddress("00:00:00:00:00:00"), sourceIp,
                            targetIp);

    pcpp::Packet packet(PACKET_SIZE);
    packet.addLayer(&ethLayer);
    packet.addLayer(&arpLayer);
    packet.computeCalculateFields();

    // set filters
    pcpp::ProtoFilter protoFilter(pcpp::ARP);
    pcpp::AndFilter andfilter;
    andfilter.addFilter(&protoFilter);
    if (!device.setFilter(andfilter)) {
        throw std::runtime_error("Failed to set BRP filter");
    };

    std::promise<pcpp::MacAddress> promise;
    std::future<pcpp::MacAddress> future = promise.get_future();
    PacketArrivalCookie cookie{&promise, targetIp};

    device.startCapture(onPacketArrives, &cookie);
    for (int i = 0; i < ARP_PING_ATTEMPTS; i++) {
        device.sendPacket(&packet);
        if (future.wait_for(ARP_TIMEOUT_DURATION) ==
            std::future_status::ready) {
            device.stopCapture();
            device.close();

            return future.get();
        };
    }

    throw std::runtime_error("No reply from ARP");
}
