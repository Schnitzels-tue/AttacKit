#include "network_scout/network_scout.h"
#include "PcapLiveDeviceList.h"

#include <vector>

std::vector<ATK::Common::DeviceInfo> ATK::Scout::getDevices() {
    auto devices =
        pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

    std::vector<ATK::Common::DeviceInfo> deviceInfoList;
    deviceInfoList.reserve(devices.size());

    for (auto *device : devices) {
        ATK::Common::DeviceInfo DeviceInfo{
            .name = device->getName(),
            .iPv4Adress = device->getIPv4Address().toString(),
            .iPv6Adress = device->getIPv6Address().toString(),
            .macAdress = device->getMacAddress().toString(),
            .active = device->captureActive()};

        deviceInfoList.emplace_back(DeviceInfo);
    }

    return deviceInfoList;
}
