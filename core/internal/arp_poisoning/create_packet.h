#pragma once

#include "IpAddress.h"
#include "MacAddress.h"
#include "Packet.h"

namespace ATK::ARP {

constexpr int MAX_PACKET_LEN = 100;

struct ArpPoisoningPacketPayload {
    pcpp::IPv4Address ipAttacker;
    pcpp::MacAddress macAttacker;
    pcpp::IPv4Address ipVictim;
    pcpp::MacAddress macVictim;
    pcpp::IPv4Address ipToSpoof;
};

/**
 * Sends a single arp poisoning packet.
 *
 * @param Payload information of the packet
 * @throws runtime_error if ARP layer fails to construct
 * @throws runtime_error if ethernet layer fails to construct
 */
pcpp::Packet createPacket(ArpPoisoningPacketPayload &payload);
} // namespace ATK::ARP
