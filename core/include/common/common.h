#pragma once

#include <string>

namespace ATK::Common {
struct InterfaceInfo {
    std::string name;
    std::string iPv4Adress;
    std::string iPv6Adress;
    std::string macAdress;
    std::string description;
};

struct DataLinkLayer {
    std::string name;
    std::string sourceMAC;
    std::string destinationMAC;
};

struct NetworkLayer {
    std::string name;
    std::string sourceIP;
    std::string destinationIP;
};

struct TransportLayer {
    std::string name;
    int sourcePort;
    int destinationPort;
};

struct PayloadLayer {
    int length;
};

struct PacketInfo {
    int length;
    std::string arrivalTime;
    DataLinkLayer dataLinkLayer;
    NetworkLayer networkLayer;
    TransportLayer transportLayer;
};
} // namespace ATK::Common
