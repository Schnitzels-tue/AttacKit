#pragma once

#include <memory>
namespace ATK::ARP {
class ArpPoisoningStrategy {
  public:
    ArpPoisoningStrategy(const ArpPoisoningStrategy &) = default;
    ArpPoisoningStrategy(ArpPoisoningStrategy &&) = delete;
    ArpPoisoningStrategy &operator=(const ArpPoisoningStrategy &) = default;
    ArpPoisoningStrategy &operator=(ArpPoisoningStrategy &&) = delete;
    ArpPoisoningStrategy() = default;
    virtual ~ArpPoisoningStrategy() = default;
    virtual void execute() = 0;
};

class ArpPoisoningContext {
  private:
    std::unique_ptr<ArpPoisoningStrategy> strategy_;

  public:
    explicit ArpPoisoningContext(
        std::unique_ptr<ArpPoisoningStrategy> &&strategy = {})
        : strategy_(std::move(strategy)) {}

    void execute() { strategy_->execute(); };
};
} // namespace ATK::ARP
