/*
    VUT FIT IPK
    1. Project - L4 Scanner
    Author: Jakub Lůčný (xlucnyj00)
    Date: 2025-03-16
*/

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <cstring>
#include <unistd.h>     //close
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <pcap.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/ip6.h>  // for struct ip6_hdr
#include <net/if.h>
#include <atomic>
#include <mutex>

#include "tcp_scanner.h"
#include "scanner-utils.h"

// Lock for printing correctly
std::mutex TCPScanner::printMutex;

/*
    Returns local IPv6 address for the current interface of scanner
    Returns empty string on error
*/
std::string TCPScanner::getLocalIPv6() {
    struct ifaddrs *ifaddr, *ifa;
    char ip[INET6_ADDRSTRLEN] = {0};

    // Get list of all available network interfaces
    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "Failed to get list of network interfaces\n";
        return "";
    }

    // Goes through the list and finds IP address for the current interface
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        // Is IPv6
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6) {
            // Matches selected interface
            if (interface_.empty() || strcmp(ifa->ifa_name, interface_.c_str()) == 0) {
                struct sockaddr_in6 *addr = (struct sockaddr_in6 *)ifa->ifa_addr;
                
                // Skip link-local addresses
                if (IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) continue;

                inet_ntop(AF_INET6, &addr->sin6_addr, ip, INET6_ADDRSTRLEN);
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
    return std::string(ip);
}

/*
    Processes captured packets
    Prints out result if it was SYN or RST packet
*/
void TCPScanner::packet_handler_v6(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet) {
    // Skip Ethernet header
    struct ip6_hdr *ip6h = (struct ip6_hdr *)(packet + 14);

    // Check if the next header is TCP
    if (ip6h->ip6_nxt != IPPROTO_TCP) return;

    // Convert source and destination addresses to string
    char srcStr[INET6_ADDRSTRLEN];
    char dstStr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6h->ip6_src, srcStr, sizeof(srcStr));
    inet_ntop(AF_INET6, &ip6h->ip6_dst, dstStr, sizeof(dstStr));

    // Skip IP header
    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + 40);

    // Get source port
    uint16_t srcPort = ntohs(tcph->source);

    // Check packet type and print result
    if (tcph->syn && tcph->ack) {
        std::lock_guard<std::mutex> lock(printMutex);
        std::cout << srcStr<< " " << srcPort << " tcp open" << std::endl;
    }
    else if (tcph->rst) {
        std::lock_guard<std::mutex> lock(printMutex);
        std::cout << srcStr << " " << srcPort << " tcp closed" << std::endl;
    }

    // Notify that the received packet was processed and end the loop
    auto data = reinterpret_cast<PacketHandlerData*>(user);
    data->packetArrived.store(true);
    pcap_breakloop(data->handle);
}

/*
    Sets up filter to capture only desired packets and starts the capture
    Starts another thread to wait the given timeout and break the loop if no packet arrived
*/
int TCPScanner::TCP_receive_packet_v6(const sockaddr_in6& destAddr6, int port) {
    char errbuff[PCAP_ERRBUF_SIZE];
    // Open a pcap session on the specified interface
    pcap_t *handle = pcap_open_live(interface_.c_str(), BUFSIZ, 1, 1000, errbuff);
    if (!handle) {
        std::cerr << "Failed to open pcap_live " << errbuff << "\n";
        return 1;
    }

    // Convert IPv6 adress to string
    char ipStr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &destAddr6.sin6_addr, ipStr, sizeof(ipStr));

    // Filter to capture only TCP packets from the specified source
    std::string filterExp = "ip6 and tcp and src host " + std::string(ipStr) + " and src port " + std::to_string(port);

    // Compile and apply the filter
    struct bpf_program filter;
    if (pcap_compile(handle, &filter, filterExp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Failed to compile filter: " << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "Failed to set filter: " << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        return 1;
    }

    // Struct to store packet handling state
    PacketHandlerData data{handle, false};

    // Start thread that waits for given timeout and breaks the loop if no packet arrived
    std::thread timerThread([&data, this, &ipStr, port]() {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_);
        // Wait for the packet to arrive
        while (!data.packetArrived.load()) {
            if (std::chrono::steady_clock::now() >= deadline) {
                pcap_breakloop(data.handle);
                std::cout << ipStr << " " << port << " tcp filtered" << std::endl;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    });

    // Start capturing packets, runs until packet arrives or timeout is reached
    pcap_loop(handle, -1, packet_handler_v6, reinterpret_cast<u_char*>(&data));

    timerThread.join();
    pcap_close(handle);

    return 0;
}

/*
    Main public method to scan a port using TCP for IPv6 address
    Takes port number and destination address as arguments
    Sends a TCP packet and waits for response
*/
int TCPScanner::scanV6(int port, const sockaddr_in6& destAddr6) {
    // Create a shared variable to store the capture result
    std::atomic<int> captureResult(0);

    // Starts capturing packets before sending the TCP packet
    // So it doesn't miss the response packet
    std::thread captureThread([&]() {
        captureResult.store(TCP_receive_packet_v6(destAddr6, port));
    });

    // Wait briefly to ensure pcap_loop is ready
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Create raw socket
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        std::cerr << "Socket creation failed (TCP IPv6)\n";
        captureThread.join();
        return 1;
    }

    // Get local IPv6 address for the given interface
    std::string localIP = getLocalIPv6();
    if (localIP.empty()) {
        std::cerr << "Failed to get local IPv6 address for interface " << interface_ << "\n";
        close(sock);
        captureThread.join();
        return 1;
    }

    // Source address structure
    struct sockaddr_in6 srcAddr6;
    memset(&srcAddr6, 0, sizeof(srcAddr6));
    srcAddr6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, localIP.c_str(), &srcAddr6.sin6_addr);

    // Construct TCP header
    struct tcphdr tcph;
    memset(&tcph, 0, sizeof(tcph));

    // Fill TCP header
    uint16_t srcPort = htons(1025 + (rand() % 64510));
    tcph.source = srcPort;
    tcph.dest = htons(port);
    tcph.seq = htonl(rand());
    tcph.ack_seq = 0;
    tcph.doff = 5;
    tcph.syn = 1;   // it's SYN packet
    tcph.window = htons(65535);
    tcph.check = 0;

    // Destination address structure for sendto
    struct sockaddr_in6 dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin6_family = AF_INET6;
    dest.sin6_port = 0;
    memcpy(&dest.sin6_addr, &destAddr6.sin6_addr, sizeof(struct in6_addr));

    // IPv6 pseudo-header for checksum calculation
    PseudoHeaderV6 psh6;
    memset(&psh6, 0, sizeof(psh6));
    psh6.src = srcAddr6.sin6_addr;
    psh6.dest = dest.sin6_addr;
    psh6.length = htonl(sizeof(tcph));
    psh6.nextHeader = IPPROTO_TCP;

    // Calculate checksum
    tcph.check = calculate_tcp_checksum(
        &tcph, sizeof(tcph),
        &psh6, sizeof(psh6)
    );

    // Set correct scope_id for local address
    if (IN6_IS_ADDR_LINKLOCAL(&dest.sin6_addr)) {
        dest.sin6_scope_id = if_nametoindex(interface_.c_str());
    } else {
        dest.sin6_scope_id = 0;     // for global
    }

    dest.sin6_flowinfo = 0;

    // Construct the packet to be send
    char packet[sizeof(tcph)];
    memcpy(packet, &tcph, sizeof(tcph));

    // Send the TCP SYN packet
    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        std::cerr << "Packet send failed (TCP IPv6). errno: " << errno << "\n";
        close(sock);
        captureThread.join();
        return 1;
    }

    close(sock);

    // Wait for the capture thread to finish
    captureThread.join();
    return captureResult.load();
}

/*********************************** IPv4 versions ************************************** */
/*
    Returns local IPv4 address for the current interface of scanner
    Returns empty string on error
*/
std::string TCPScanner::getLocalIPv4() {
    struct ifaddrs *ifaddr, *ifa;
    char ip[INET_ADDRSTRLEN] = {0};

    // Get list of all available network interfaces
    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "Failed to get list of network interfaces\n";
        return "";
    }

    // Goes through the list and finds IP address for the current interface
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        // Is IPv4
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            // Matches selected interface
            if (interface_.empty() || strcmp(ifa->ifa_name, interface_.c_str()) == 0) {
                struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
    return std::string(ip);
}

/*
    Processes captured packets
    Prints out result if it was SYN or RST packet
*/
void TCPScanner::packet_handler_v4(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet) {
    // Skip Ethernet header
    struct iphdr *iph = (struct iphdr *)(packet + 14);
    
    // Check if the next header is TCP
    if (iph->protocol != IPPROTO_TCP) return;

    // Skip IP header
    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + (iph->ihl * 4));

    uint16_t srcPort = ntohs(tcph->source);

    // Determines if socket is closed or open based on the packet type
    if (tcph->syn && tcph->ack) {
        std::lock_guard<std::mutex> lock(printMutex);
        std::cout << inet_ntoa(*(in_addr *)&iph->saddr) << " " << srcPort << " tcp open" << std::endl;
    }
    else if (tcph->rst) {
        std::lock_guard<std::mutex> lock(printMutex);
        std::cout << inet_ntoa(*(in_addr *)&iph->saddr) << " " << srcPort << " tcp closed" << std::endl;
    }

    // Notify that the received packet was processed and end the loop
    auto data = reinterpret_cast<PacketHandlerData*>(user);
    data->packetArrived.store(true);
    pcap_breakloop(data->handle);
}

/*
    Sets up filter to capture only desired packets and starts the capture
    Starts another thread to wait the given timeout and break the loop if no packet arrived
    Listens for responses using libpcap
*/
int TCPScanner::TCP_receive_packet_v4(const sockaddr_in& destAddr4, int port) { 
    char errbuff[PCAP_ERRBUF_SIZE];
    // Open a pcap session on the specified interface
    pcap_t *handle = pcap_open_live(interface_.c_str(), BUFSIZ, 1, 1000, errbuff);
    if (!handle) {
        std::cerr << "pcap_open_live failed: " << errbuff << "\n";
        return 1;
    }

    std::string ipStr = inet_ntoa(destAddr4.sin_addr);

    // Filter to capture only TCP packets from the specified source
    std::string filterExp = "tcp and src " + ipStr + " and src port " + std::to_string(port);

    // Compile and apply the filter
    struct bpf_program filter;
    if (pcap_compile(handle, &filter, filterExp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "Failed to set filter" << "\n";
        pcap_close(handle);
        return 1;
    }

    // Struct to store packet handling state
    PacketHandlerData data{handle, false};

    // Start thread that waits for given timeout and breaks the loop if no packet arrived
    std::thread timerThread([&data, this, &ipStr, port]() {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_);
        // Wait for the packet to arrive
        while (!data.packetArrived.load()) {
            if (std::chrono::steady_clock::now() >= deadline) {
                pcap_breakloop(data.handle);
                std::lock_guard<std::mutex> lock(printMutex);
                std::cout << ipStr << " " << port << " tcp filtered" << std::endl;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    });

    // Start capturing packets, runs until packet arrives or timeout is reached
    pcap_loop(handle, -1, packet_handler_v4, reinterpret_cast<u_char*>(&data));

    timerThread.join();
    pcap_close(handle);

    return 0;
}

/*
    Main public method to scan a port using TCP for IPv4 address
    Works the same as IPv6 version
    Takes port number and destination address as arguments
    Sends a TCP packet and waits for response
*/
int TCPScanner::scanV4(int port, const sockaddr_in& destAddr4) {
    // Create a shared variable to store the capture result
    std::atomic<int> captureResult(0);

    // Starts capturing packets before sending the TCP packet
    // So it doesn't miss the response packet
    std::thread captureThread([&]() {
        captureResult.store(TCP_receive_packet_v4(destAddr4, port));
    });

    // Wait briefly to ensure pcap_loop is ready
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Create raw socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    // Set socket options to have control over the IP header
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt(IP_HDRINCL) failed");
        close(sock);
        return 1;
    }

    // Allocate memory for the packet and set it whole to zero
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    // Create IP and TCP headers
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // Destination address structure for sendto
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr = destAddr4.sin_addr;

    // Fill IP header
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(packet));
    iph->id = htons(rand());
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    // Get local IPv4 address for the given interface
    std::string localIP = getLocalIPv4();
    if (localIP.empty()) {
        std::cerr << "Failed to get local IP address!\n";
        close(sock);
        return 1;
    }

    iph->saddr = inet_addr(localIP.c_str());
    iph->daddr = dest.sin_addr.s_addr;
    iph->check = 0;
    iph->check = checksum(iph, sizeof(struct iphdr));

    // Fill TCP header
    tcph->source = htons(1025 + (rand() % 64510));
    tcph->dest = htons(port);
    tcph->seq = htonl(rand());
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(65535);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // Pseudo-header for checksum calculation
    struct PseudoHeader psh;
    psh.src_addr = iph->saddr;
    psh.dest_addr = iph->daddr;
    psh.reserved = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    // Calculate checksum for pseudopacket
    char pseudo_packet[sizeof(PseudoHeader) + sizeof(struct tcphdr)];
    memcpy(pseudo_packet, &psh, sizeof(PseudoHeader));
    memcpy(pseudo_packet + sizeof(PseudoHeader), tcph, sizeof(struct tcphdr));
    tcph->check = checksum(pseudo_packet, sizeof(pseudo_packet));

    // Send packet
    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        std::cerr << "Packet send failed (TCP IPv4). errno: " << errno << std::endl;
        close(sock);
        captureThread.join();
        return 1;
    }
    close(sock);

    // Wait for the capture thread to finish
    captureThread.join();
    return captureResult.load();
}
