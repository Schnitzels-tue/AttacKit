#include <string>
namespace ATK::Common {
struct DeviceInfo {
    std::string name;
    std::string iPv4Adress;
    std::string iPv6Adress;
    std::string macAdress;
    bool active;
};
} // namespace ATK::Common
