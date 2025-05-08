#include "network_scout/network_scout.h"
#include <iostream>
#include <vector>

int main() {
    std::vector<ATK::Common::DeviceInfo> devices = ATK::Scout::getDevices();

    std::cout << "===========" << "\n";
    for (const ATK::Common::DeviceInfo &device : devices) {
        std::cout << "Name: " << device.name << "\n";
        std::cout << "IPv4: " << device.iPv4Adress << "\n";
        std::cout << "IPV6: " << device.iPv6Adress << "\n";
        std::cout << "MAC: " << device.macAdress << "\n";
        std::cout << (device.active ? "Active" : "Inactive") << "\n";
        std::cout << "===========" << "\n";
    }
}
