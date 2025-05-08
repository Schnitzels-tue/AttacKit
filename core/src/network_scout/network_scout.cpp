#include "network_scout/network_scout.h"
#include "PcapLiveDeviceList.h"

#include <vector>

std::vector<Scout::DeviceInfo> Scout::getDevices() {
    auto devices =
        pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

    std::vector<Scout::DeviceInfo> deviceInfoList;
    deviceInfoList.reserve(devices.size());

    for (auto *device : devices) {
        DeviceInfo DeviceInfo{.name = device->getName(),
                              .iPv4Adress = device->getIPv4Address().toString(),
                              .iPv6Adress = device->getIPv6Address().toString(),
                              .macAdress = device->getMacAddress().toString(),
                              .description = device->getDesc(),
                              .active = device->captureActive()};

        deviceInfoList.emplace_back(DeviceInfo);
    }

    return deviceInfoList;
}
