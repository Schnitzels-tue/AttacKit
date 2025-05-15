#pragma once

#include "PcapLiveDevice.h"
#include "RawPacket.h"
#include <memory>
namespace ATK::DNS {
/**
 * DNS poisoning execution strategy.
 */
class DnsPoisoningStrategy {
  public:
    DnsPoisoningStrategy(const DnsPoisoningStrategy &) = default;
    DnsPoisoningStrategy(DnsPoisoningStrategy &&) = delete;
    DnsPoisoningStrategy &operator=(const DnsPoisoningStrategy &) = default;
    DnsPoisoningStrategy &operator=(DnsPoisoningStrategy &&) = delete;
    DnsPoisoningStrategy() = default;
    virtual ~DnsPoisoningStrategy() = default;

    /**
     * Execute the DNS Attack
     *
     * @throws runtime_error if class is misconfigured (e.g, interface not
     * compatible with DNS, failed to send packet).
     */
    virtual void execute() = 0;

  private:
    /**
     * Packet handler method used in conjunction with PcapPlusplus' startCapture
     */
    virtual void onPacketArrives(pcpp::RawPacket *packet,
                                 pcpp::PcapLiveDevice *device,
                                 void *cookie) = 0;

  protected:
    // TODO confirm size
    static constexpr int DNS_PACKET_SIZE = 512;
};

/**
 * DNS poisoning execution context, uses the strategy pattern.
 */
class DnsPoisoningContext {
  private:
    std::unique_ptr<DnsPoisoningStrategy> strategy_;

  public:
    explicit DnsPoisoningContext(
        std::unique_ptr<DnsPoisoningStrategy> &&strategy = {})
        : strategy_(std::move(strategy)) {}

    /**
     * Execute the DNS attack
     */
    void execute() { strategy_->execute(); };
};
} // namespace ATK::DNS
