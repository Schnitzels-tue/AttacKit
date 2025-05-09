#include "network_scout/network_scout.h"
#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"
#include "common/common.h"
#include "common/pcap_to_common.h"

std::vector<ATK::Common::InterfaceInfo> ATK::Scout::getInterfaces() {
    auto devices =
        pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

    std::vector<ATK::Common::InterfaceInfo> deviceInfoList;
    deviceInfoList.reserve(devices.size());

    for (const pcpp::PcapLiveDevice *device : devices) {
        deviceInfoList.emplace_back(ATK::Common::toInterfaceInfo(*device));
    }

    return deviceInfoList;
} // namespace ATK::Scout
