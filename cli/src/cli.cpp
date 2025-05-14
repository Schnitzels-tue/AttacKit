

#include "arp_poisoning/public.h"

int main(int argc, char *argv[]) {
    ATK::ARP::AllOutPoisoningOptions options{.ifaceIpOrName = "en0"};

    ATK::ARP::allOutPoison(options);
}
