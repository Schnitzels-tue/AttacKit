#pragma once

#include <string>

namespace ARP {

struct ArpPoisoningOptions {
    std::string ipAttacker;
    std::string macAttacker;
    std::string ipVictim;
    std::string macVictim;
    std::string ipToSpoof;
    std::string deviceName;
};

void poisonArp(ArpPoisoningOptions &options);
} // namespace ARP
