#pragma once

#include "PcapLiveDevice.h"
#include "RawPacket.h"
#include <memory>
namespace ATK::ARP {
/**
 * Arp poisoning execution strategy.
 */
class ArpPoisoningStrategy {
  public:
    ArpPoisoningStrategy(const ArpPoisoningStrategy &) = default;
    ArpPoisoningStrategy(ArpPoisoningStrategy &&) = delete;
    ArpPoisoningStrategy &operator=(const ArpPoisoningStrategy &) = default;
    ArpPoisoningStrategy &operator=(ArpPoisoningStrategy &&) = delete;
    ArpPoisoningStrategy() = default;
    virtual ~ArpPoisoningStrategy() = default;

    /**
     * Execute the Arp Attack
     *
     * @throws runtime_error if class is misconfigured(e.g, interface not
     * copmatible with arp, failed to send packet).
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
    static constexpr int ARP_PACKET_SIZE = 42;
};

/**
 * Arp poisoning execution context, uses the strategy pattern.
 */
class ArpPoisoningContext {
  private:
    std::unique_ptr<ArpPoisoningStrategy> strategy_;

  public:
    explicit ArpPoisoningContext(
        std::unique_ptr<ArpPoisoningStrategy> &&strategy = {})
        : strategy_(std::move(strategy)) {}

    /**
     * Execute the arp attack
     */
    void execute() { strategy_->execute(); };
};
} // namespace ATK::ARP
