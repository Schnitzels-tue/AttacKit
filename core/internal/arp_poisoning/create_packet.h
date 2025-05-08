#pragma once

#include "IpAddress.h"
#include "MacAddress.h"
#include "Packet.h"

namespace ARP {

constexpr int MAX_PACKET_LEN = 100;

struct ArpPoisoningPacketPayload {
    pcpp::IPv4Address ipAttacker;
    pcpp::MacAddress macAttacker;
    pcpp::IPv4Address ipVictim;
    pcpp::MacAddress macVictim;
    pcpp::IPv4Address ipToSpoof;
};

pcpp::Packet createPacket(ArpPoisoningPacketPayload &payload);
} // namespace ARP
