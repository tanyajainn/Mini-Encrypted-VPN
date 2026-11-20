#pragma once
#include <string>
int tun_open(const std::string& name);
// Only reports readiness once the kernel interface exists and is administratively UP.
// This is not a substitute for an authenticated handshake or route verification.
bool tun_wait_up(const std::string& name, unsigned timeout_ms);
