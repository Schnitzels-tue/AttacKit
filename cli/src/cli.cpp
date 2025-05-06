#include "helper.h"

#include <core.h>

int main() {
    ARP::useHelper();
    helper();

    ARP::poisonArp();
    return 0;
}
