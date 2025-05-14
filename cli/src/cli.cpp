#include "arp_poisoning/public.h"
#include "log.h"
#include <exception>

int main(int argc, char *argv[]) noexcept {
    try {
        const ATK::ARP::AllOutPoisoningOptions options{.ifaceIpOrName = "en0"};

        LOG_ERROR(argc);
        LOG_ERROR(*argv);
        ATK::ARP::allOutPoison(options);
    } catch (std::exception &e) {
        LOG_ERROR(e.what());

        return 1;
    }

    return 0;
}
