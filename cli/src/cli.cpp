#include "arp_poisoning/arp_poisoning.h"
int main() {
    ARP::ArpPoisoningOptions options{"", "", "", "", "", ""};
    ARP::poisonArp(options);
    return 0;
}
