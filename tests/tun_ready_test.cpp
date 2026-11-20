#include "tun.h"
#include <iostream>
#include <stdexcept>

int main() {
    if (!tun_wait_up("lo", 200)) throw std::runtime_error("loopback should be UP");
    if (tun_wait_up("definitely-no-tun", 5))
        throw std::runtime_error("missing network device should time out");
    if (tun_wait_up("", 5)) throw std::runtime_error("empty interface must reject");
    std::cout << "PASS: readiness detection on UP, missing and empty interfaces\n";
}
