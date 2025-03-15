#include "scanner.h"
#include <iostream>
#include <iomanip>
#include <thread>
#include <vector>
#include <sys/socket.h>
#include <sys/types.h>
#include <ifaddrs.h>


Scanner::Scanner(const std::string &iface, const std::string &target, 
                 const std::vector<int> &tcp_ports, const std::vector<int> &udp_ports, 
                 int timeout)
    : interface(iface), target(target), tcp_ports(tcp_ports), udp_ports(udp_ports), timeout(timeout) {}

void Scanner::startScan() {
    std::cout << "Starting scan on " << target << " via interface " << interface << "\n";

    // Start TCP scan in a separate thread
    std::thread tcp_thread(&Scanner::scanTCP, this);

    // Start UDP scan in another thread
    std::thread udp_thread(&Scanner::scanUDP, this);

    // Wait for both to complete
    tcp_thread.join();
    udp_thread.join();
}

void Scanner::scanTCP() {
    std::cout << "[TCP Scan] Scanning target: " << target << "\n";
    for (int port : tcp_ports) {
        std::cout << "[TCP] Checking port " << port << "...\n";
        // TODO: Send SYN packet and analyze response
    }
}

void Scanner::scanUDP() {
    std::cout << "[UDP Scan] Scanning target: " << target << "\n";
    for (int port : udp_ports) {
        std::cout << "[UDP] Checking port " << port << "...\n";
        // TODO: Send UDP packet and analyze ICMP response
    }
}

/*
    Prints out a list of available network interfaces
*/
void Scanner::listInterfaces() {
    struct ifaddrs* ifaddr;
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }

    std::cout << "Available Network Interfaces:\n";
    for (struct ifaddrs* iface = ifaddr; iface != nullptr; iface = iface->ifa_next) {
        if (iface->ifa_addr == nullptr) continue;  // Skip interfaces with no address

        auto family = iface->ifa_addr->sa_family;

        auto family_name = "AF_INET";
        if (family == AF_INET6){
            family_name = "AF_INET6";
        }
        else if (family == AF_PACKET){
            family_name = "AF_PACKET";
        }

        std::cout << " - " << std::left << std::setw(16) << iface->ifa_name << " " << family_name << "\n";    }

    freeifaddrs(ifaddr);
}
