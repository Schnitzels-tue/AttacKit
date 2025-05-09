#include "network_scout/sniffing.h"
#include <iostream>

constexpr int NUM_PACKETS = 10;

int main() {
    auto packets = ATK::Scout::sniffPackets("en0", NUM_PACKETS);

    for (const auto &packet : packets) {
        std::cout << packet.networkLayer.sourceIP << "\n";
    }
}
