#include "network_scout/network_scout.h"
#include <iostream>
#include <vector>

int main() {
    std::vector<ATK::Common::DeviceInfo> devices = ATK::Scout::getInterfaces();
    std::cout << "===========" << "\n";
    for (const ATK::Common::DeviceInfo &device : devices) {
        std::cout << "Name: " << device.name << "\n";
        std::cout << "IPv4: " << device.iPv4Adress << "\n";
        std::cout << "IPV6: " << device.iPv6Adress << "\n";
        std::cout << "MAC: " << device.macAdress << "\n";
        std::cout << (device.active ? "Active" : "Inactive") << "\n";
        std::cout << "===========" << "\n";
    }

    auto packets = ATK::Scout::sniffPackets("en0", 10);

    for (const auto &packet : packets) {
        std::cout << packet.sourceIP << "\n";
    }
}
