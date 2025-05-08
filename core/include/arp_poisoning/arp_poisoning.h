#pragma once

#include <string>

namespace ATK::ARP {

struct ArpPoisoningOptions {
    std::string ipAttacker;
    std::string macAttacker;
    std::string ipVictim;
    std::string macVictim;
    std::string ipToSpoof;
    std::string deviceName;
};

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
void poisonArp(ArpPoisoningOptions &options);
} // namespace ATK::ARP
