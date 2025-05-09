#include "network_scout/network_scout.h"
#include "PcapLiveDeviceList.h"
#include "common/common.h"

std::vector<ATK::Common::InterfaceInfo> ATK::Scout::getInterfaces() {
    auto devices =
        pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

    std::vector<ATK::Common::InterfaceInfo> deviceInfoList;
    deviceInfoList.reserve(devices.size());

    for (auto *device : devices) {
        ATK::Common::InterfaceInfo DeviceInfo{
            .name = device->getName(),
            .iPv4Adress = device->getIPv4Address().toString(),
            .iPv6Adress = device->getIPv6Address().toString(),
            .macAdress = device->getMacAddress().toString(),
            .active = device->captureActive()};

        deviceInfoList.emplace_back(DeviceInfo);
    }

    return deviceInfoList;
} // namespace std::vector
