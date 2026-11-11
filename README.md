# 🔐 Mini Encrypted VPN

A lightweight VPN-style encrypted tunneling project built from scratch to understand how VPNs work under the hood.

## 📌 Overview

This project demonstrates the core ideas behind a VPN by creating a client-server tunnel that transports encrypted network traffic. It uses Linux networking features inside **Ubuntu on WSL2**, allowing a simulated VPN environment to run on Windows without requiring two physical machines.

The project focuses on learning rather than replacing production VPN software.

## 🧠 How It Works

```text
Client
  │
  ▼
Virtual Network Interface
  │
  ▼
VPN Client
  │
  ▼
Encrypt
  │
  ▼
UDP Tunnel 🔒
  │
  ▼
VPN Server
  │
  ▼
Decrypt
  │
  ▼
Forward Traffic
```

Traffic is routed through the virtual network, encrypted before being transported through the tunnel, and decrypted on the server side before forwarding.

## 🛠️ Technologies Used

- Ubuntu / Linux
- WSL2
- Network namespaces
- Virtual network interfaces
- IP routing
- UDP sockets
- Encryption
- Packet forwarding
- Bash scripting
- CMake

## 💻 Environment

The project was developed on:

- **Host OS:** Windows
- **Linux environment:** WSL2
- **Distribution:** Ubuntu

## 🚀 Running the Project

Clone the repository:

```bash
git clone <your-repository-url>
cd <repository-name>
```

Make the setup script executable:

```bash
chmod +x run_vpn.sh
```

Run the VPN environment:

```bash
./run_vpn.sh
```

The script sets up the required network namespaces, virtual interfaces, routing, and VPN components.

## 📁 Project Structure

```text
vpn-project/
├── client/
├── server/
├── run_vpn.sh
├── CMakeLists.txt
├── README.md
└── LICENSE
```

The exact structure may vary depending on the implementation.

## 🔒 Security

The project demonstrates the principle of encrypting traffic before it travels through a network tunnel. This provides a practical introduction to confidentiality and secure communication.

However, this is an **educational implementation** and should not be treated as production-grade VPN software. It does not guarantee anonymity, prevent all tracking, or automatically provide geographical IP masking.

## 🆚 How Is This Different From NordVPN?

Commercial VPN services provide large networks of geographically distributed servers, public IP replacement, authentication, DNS protection, kill switches, advanced protocols, and production-grade security.

This project focuses on understanding the underlying concepts:

**tunneling + encryption + routing + packet forwarding + client/server networking**

## 🎯 What I Learned

Building this project provided hands-on experience with:

- Network packets and IP addressing
- UDP communication
- Routing tables
- Linux network namespaces
- Virtual network interfaces
- Encryption
- Client-server architecture
- Packet forwarding
- Linux networking
- WSL2
- Bash automation
- VPN architecture

## 🔮 Future Improvements

Possible improvements include:

- Stronger authentication
- Better key management
- Multiple client support
- Improved error handling
- Performance benchmarking
- Packet-loss handling
- Deployment across separate physical machines
- A graphical client

## ⚠️ Disclaimer

This project is intended for educational and experimentation purposes. It is not designed to replace established VPN solutions such as WireGuard, OpenVPN, or commercial VPN services.

## 👩‍💻 Author

**Tanya Jain**

Built as a hands-on cybersecurity and networking project to understand the architecture and mechanics of encrypted VPN tunnels.

## 📜 License

This project is licensed under the **MIT License**. See `LICENSE` for details.

## Replay-window experiment

How often does the receiver discard a legitimate packet that arrives late?
The receiver tracks the last 64 sequence positions in a bitmap. An unseen
packet whose sequence is 64 or more behind the highest accepted sequence
falls outside the window.

Build with testing enabled, then run:

```bash
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build
(cd build && ctest --output-on-failure)
./build/replay_study > replay-results.csv
```

Each run sends 4,096 distinct sequence IDs one tick apart. A seeded generator
adds an integer delay from zero to the selected maximum. Ties preserve send
order. An immediate second delivery of each ID checks duplicate rejection.
Five seeds and five delay bounds are shared across all three window widths.
The 64-position production bitmap is checked against a set-based reference
on every delivery. The 32- and 128-position alternatives use the reference only.

With a maximum delay of 128 ticks, late original drops across five seeds
were 13,029/20,480 (32 positions), 7,981/20,480 (64), and 0/20,480 (128).
Every scenario rejected every second delivery. Results describe simulated
sequence arrivals after authentication. Real network timing, cryptographic
cost and tunnel throughput require separate measurements.
