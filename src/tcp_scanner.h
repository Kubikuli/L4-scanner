/*
    VUT FIT IPK
    1. Project - L4 Scanner
    Author: Jakub Lůčný (xlucnyj00)
    Date: 2025-03-16
*/

#ifndef TCP_SCANNER_H
#define TCP_SCANNER_H

#include <string>
#include <mutex>

// A class for scanning TCP ports on IPv4 or IPv6 networks
// Sends packet to specified port and prints out port status
class TCPScanner {
public:
    // Constructor, takes interface network to use for scanning and timeout
    TCPScanner(const std::string& interface, int timeout): interface_(interface), timeout_(timeout) {}
    // Main public function to scan a port using UDP
    // Takes port number and destination address as arguments
    int scanV4(int port, const sockaddr_in& destAddr4);
    // Same as scanV4 but for IPv6
    int scanV6(int port, const sockaddr_in6& destAddr6);

private:
    // private helper functions
    static std::mutex printMutex;
    // Returns local IP address for the current interface of scanner
    std::string getLocalIPv6();
    std::string getLocalIPv4();
    // Processes received packets
    static void packet_handler_v6(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet);
    static void packet_handler_v4(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet);
    // Sets up filter for received packets and starts listening
    int TCP_receive_packet_v6(const sockaddr_in6& destAddr6, int scannedPort);
    int TCP_receive_packet_v4(const sockaddr_in& destAddr4, int scannedPort);

    std::string interface_;
    int timeout_;
};

#endif // TCP_SCANNER_H
