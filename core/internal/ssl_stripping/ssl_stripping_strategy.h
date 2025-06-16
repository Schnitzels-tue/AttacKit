#pragma once

#include <memory>

namespace ATK::SSL {
/**
 * Ssl stripping execution strategy.
 */
class SslStrippingStrategy {
  public:
    SslStrippingStrategy(const SslStrippingStrategy &) = default;
    SslStrippingStrategy(SslStrippingStrategy &&) = delete;
    SslStrippingStrategy &operator=(const SslStrippingStrategy &) = default;
    SslStrippingStrategy &operator=(SslStrippingStrategy &&) = delete;
    SslStrippingStrategy() = default;
    virtual ~SslStrippingStrategy() = default;

    /**
     * Execute the Arp Attack
     *
     * @throws runtime_error if class is misconfigured(e.g, interface not
     * copmatible with arp, failed to send packet).
     */
    virtual void execute() = 0;
};

/**
 * Ssl stripping execution context, uses the strategy pattern.
 */
class SslStrippingContext {
  private:
    std::unique_ptr<SslStrippingStrategy> strategy_;

  public:
    explicit SslStrippingContext(
        std::unique_ptr<SslStrippingStrategy> &&strategy = {})
        : strategy_(std::move(strategy)) {}

    /**
     * Execute the arp attack
     */
    void execute() { strategy_->execute(); };
};
} // namespace ATK::SSL
