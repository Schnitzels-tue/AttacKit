#include "common/common.h"
#include <vector>

namespace ATK::Scout {
/**
 * Sniffs packets and returns their information.
 *
 * @param deviceIpOrName Ip or name of interface to sniff
 * @param packets Number of packets to spoof
 *
 * @throws invalid_argument if device is not a valid device
 * @throws runtime_error if device cannot be connected to
 */
std::vector<ATK::Common::PacketInfo>
sniffPackets(const std::string &deviceIpOrName, int numPackets);
} // namespace ATK::Scout
