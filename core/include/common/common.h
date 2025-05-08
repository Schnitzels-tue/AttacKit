#include <string>

namespace ATK::Common {
struct DeviceInfo {
    std::string name;
    std::string iPv4Adress;
    std::string iPv6Adress;
    std::string macAdress;
    bool active;
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
    std::string sourcePort;
    std::string destinationPort;
};

struct PacketInfo {
    DataLinkLayer dataLinkLayer;
    NetworkLayer networkLayer;
    TransportLayer transportLayer;
};
} // namespace ATK::Common
