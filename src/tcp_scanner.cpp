#include <iostream>
#include <vector>
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
#include <sys/select.h>

#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/ip6.h>  // for struct ip6_hdr
#include <net/if.h>

#include <atomic>
#include <mutex>
#include <condition_variable>

// Pseudo-header for checksum calculation
struct PseudoHeader {
    uint32_t src_addr;
    uint32_t dest_addr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_length;
};

static std::mutex printMutex;

// Function to calculate checksum
uint16_t checksum(void *buffer, int length) {
    uint32_t sum = 0;
    uint16_t *ptr = static_cast<uint16_t *>(buffer);

    while (length > 1) {
        sum += *ptr++;
        length -= 2;
    }
    if (length == 1) {
        sum += *(reinterpret_cast<uint8_t *>(ptr));
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}

// Define a single pseudo-header-based checksum function
uint16_t calculate_tcp_checksum(void *tcp_header, int tcp_length, void *pseudo_header, int pseudo_length) {
    char buffer[pseudo_length + tcp_length];
    memcpy(buffer, pseudo_header, pseudo_length);
    memcpy(buffer + pseudo_length, tcp_header, tcp_length);
    return checksum(buffer, sizeof(buffer));
}

// Create a pseudo-header struct for IPv6
struct PseudoHeaderV6 {
    struct in6_addr src;
    struct in6_addr dest;
    uint32_t length;
    uint8_t zero[3];
    uint8_t nextHeader;
} __attribute__((packed));

std::string getLocalIPv6(const std::string& interface) {
    struct ifaddrs *ifaddr, *ifa;
    char ip[INET6_ADDRSTRLEN] = {0};

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return "";
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6) {
            if (interface.empty() || strcmp(ifa->ifa_name, interface.c_str()) == 0) {
                struct sockaddr_in6 *addr = (struct sockaddr_in6 *)ifa->ifa_addr;
                
                // Skip link-local addresses (starting with fe80::)
                if (IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) continue;

                inet_ntop(AF_INET6, &addr->sin6_addr, ip, INET6_ADDRSTRLEN);
                break;  // Found the first valid global IPv6 address
            }
        }
    }

    freeifaddrs(ifaddr);
    return std::string(ip);
}

// A small struct to pass both handle and "packetArrived" flag to pcap_loop and its handler
struct PacketHandlerData {
    pcap_t* handle;
    std::atomic<bool> packetArrived;
};



// This function is called every time an IPv6 packet is captured
void packet_handler_v6(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet) {
    // Skip Ethernet header (14 bytes)
    struct ip6_hdr *ip6h = (struct ip6_hdr *)(packet + 14);

    // If the next header isn't TCP, ignore
    if (ip6h->ip6_nxt != IPPROTO_TCP) return;

    // Convert source/destination addresses to string
    char srcStr[INET6_ADDRSTRLEN];
    char dstStr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6h->ip6_src, srcStr, sizeof(srcStr));
    inet_ntop(AF_INET6, &ip6h->ip6_dst, dstStr, sizeof(dstStr));

    // The base IPv6 header is 40 bytes, parse TCP header afterward
    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + 40);

    uint16_t srcPort = ntohs(tcph->source);

    if (tcph->syn && tcph->ack) {
        std::lock_guard<std::mutex> lock(printMutex);
        std::cout << srcStr<< " " << srcPort << " tcp open" << std::endl;
    } else if (tcph->rst) {
        std::lock_guard<std::mutex> lock(printMutex);
        std::cout << srcStr << " " << srcPort << " tcp closed" << std::endl;
    }

    auto data = reinterpret_cast<PacketHandlerData*>(user);
    data->packetArrived.store(true);
    pcap_breakloop(data->handle);
}


/*********************************************************************************** */
int TCP_recieve_packet_v6(const std::string& interface, const sockaddr_in6& destAddr6, int scannedPort, int timeout) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live failed: " << errbuf << std::endl;
        return 1;
    }

    char ipStr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &destAddr6.sin6_addr, ipStr, sizeof(ipStr));
    std::string filterExp = "ip6 and tcp and src host " + std::string(ipStr) + " and src port " + std::to_string(scannedPort);

    struct bpf_program filter;
    if (pcap_compile(handle, &filter, filterExp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "pcap_compile failed: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "pcap_setfilter failed: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }

    PacketHandlerData data{handle, false};

    std::thread timerThread([&data, timeout, &ipStr, scannedPort]() {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
        while (!data.packetArrived.load()) {
            if (std::chrono::steady_clock::now() >= deadline) {
                pcap_breakloop(data.handle);
                std::cout << ipStr << " " << scannedPort << " tcp filtered\n";
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    });

    // Start capturing packets
    pcap_loop(handle, -1, packet_handler_v6, reinterpret_cast<u_char*>(&data));

    timerThread.join();
    pcap_close(handle);

    return 0;
}

/****************************************************************************** */
int TCP_scan_v6(const int &tcpPort, const sockaddr_in6& destAddr6, const std::string& interface, int timeout) {
    // Create a shared variable to store the capture result
    std::atomic<int> captureResult(0);

    // Start packet capture in a background thread
    std::thread captureThread([&]() {
        captureResult.store(TCP_recieve_packet_v6(interface, destAddr6, tcpPort, timeout));
    });

    // Wait briefly to ensure pcap_loop is ready
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Create raw socket for TCP over IPv6
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        std::cerr << "Socket creation failed (TCP IPv6)";
        captureThread.join();
        return 1;
    }

    // Get local IPv6 address for the given interface
    std::string localIP = getLocalIPv6(interface);
    if (localIP.empty()) {
        std::cerr << "Failed to get local IPv6 address for interface " << interface << std::endl;
        close(sock);
        captureThread.join();
        return 1;
    }

    struct sockaddr_in6 srcAddr6;
    memset(&srcAddr6, 0, sizeof(srcAddr6));
    srcAddr6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, localIP.c_str(), &srcAddr6.sin6_addr);

    // Construct TCP header
    struct tcphdr tcph;
    memset(&tcph, 0, sizeof(tcph));

    // Fill TCP header
    uint16_t srcPort = htons(1025 + (rand() % 64510));  // Random source port
    tcph.source = srcPort;
    tcph.dest = htons(tcpPort);
    tcph.seq = htonl(rand());
    tcph.ack_seq = 0;
    tcph.doff = 5;
    tcph.syn = 1;
    tcph.window = htons(65535);
    tcph.check = 0;

    // Destination structure for sendto
    struct sockaddr_in6 dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin6_family = AF_INET6;
    dest.sin6_port = 0;
    memcpy(&dest.sin6_addr, &destAddr6.sin6_addr, sizeof(struct in6_addr));

    // Build IPv6 pseudo-header
    PseudoHeaderV6 psh6;
    memset(&psh6, 0, sizeof(psh6));
    psh6.src = srcAddr6.sin6_addr;
    psh6.dest = dest.sin6_addr;
    psh6.length = htonl(sizeof(tcph));
    psh6.nextHeader = IPPROTO_TCP;

    // Calculate checksum using the unified function
    tcph.check = calculate_tcp_checksum(
        &tcph, sizeof(tcph),
        &psh6, sizeof(psh6)
    );
    
    if (IN6_IS_ADDR_LINKLOCAL(&dest.sin6_addr)) {
        dest.sin6_scope_id = if_nametoindex(interface.c_str());
    } else {
        dest.sin6_scope_id = 0;  // Ensure it's zero for global addresses
    }
    
    dest.sin6_flowinfo = 0;
    
    char packet[sizeof(tcph)];
    memcpy(packet, &tcph, sizeof(tcph));

    // Send the TCP segment (without IPv6 header)
    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        std::cerr << "Packet send failed (TCP IPv6). errno: " << errno << std::endl;
        close(sock);
        captureThread.join();
        return 1;
    }

    close(sock);

    // Wait for the capture thread to finish
    captureThread.join();
    return captureResult.load();
}


/******************************************************************************************** */
// Gets current user's IP address
std::string getLocalIPv4(const std::string& interface) {
    struct ifaddrs *ifaddr, *ifa;
    char ip[INET_ADDRSTRLEN] = {0};

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return "";
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            if (interface.empty() || strcmp(ifa->ifa_name, interface.c_str()) == 0) {
                struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
                break;  // Found the first valid IPv4 address
            }
        }
    }

    freeifaddrs(ifaddr);
    return std::string(ip);
}

// This function is called every time a packet is captured
void packet_handler_v4(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet) {
    struct iphdr *iph = (struct iphdr *)(packet + 14);  // Skip Ethernet header
    if (iph->protocol != IPPROTO_TCP) return;

    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + (iph->ihl * 4));  // TCP header

    uint16_t srcPort = ntohs(tcph->source);

    // Determines if socket is closed or open based on the received packet
    if (tcph->syn && tcph->ack) {
        std::lock_guard<std::mutex> lock(printMutex);
        std::cout << inet_ntoa(*(in_addr *)&iph->saddr) << " " << srcPort << " tcp open" << std::endl;
    } else if (tcph->rst) {
        std::lock_guard<std::mutex> lock(printMutex);
        std::cout << inet_ntoa(*(in_addr *)&iph->saddr) << " " << srcPort << " tcp closed" << std::endl;
    }

    auto data = reinterpret_cast<PacketHandlerData*>(user);
    data->packetArrived.store(true);
    pcap_breakloop(data->handle);
}

/*********************************************************************************** */
// Open handle for the packet capture
int TCP_recieve_packet_v4(const std::string& interface, const sockaddr_in& destAddr4, int timeout, int scannedPort) { 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live failed: " << errbuf << std::endl;
        return 1;
    }

    std::string ipStr = inet_ntoa(destAddr4.sin_addr);
    std::string filterExp = "tcp and src " + ipStr + " and src port " + std::to_string(scannedPort);

    struct bpf_program filter;
    if (pcap_compile(handle, &filter, filterExp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "Failed to set filter" << std::endl;
        pcap_close(handle);
        return 1;
    }

    PacketHandlerData data{handle, false};

    // Start a timer thread that waits up to 'timeout' ms, then breaks loop if no packet arrived
    std::thread timerThread([&data, timeout, &ipStr, scannedPort]() {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
        while (!data.packetArrived.load()) {
            if (std::chrono::steady_clock::now() >= deadline) {
                pcap_breakloop(data.handle);
                std::lock_guard<std::mutex> lock(printMutex);
                std::cout << ipStr << " " << scannedPort << " tcp filtered\n";
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    });

    // Use data struct as user param
    pcap_loop(handle, -1, packet_handler_v4, reinterpret_cast<u_char*>(&data));

    timerThread.join();
    pcap_close(handle);

    return 0;
}

/**************************************************************************************** */
int TCP_scan_v4(const int &tcpPort, const sockaddr_in& destAddr4, const std::string& interface, int timeout) {
    // create raw socket
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

    // Allocate memory for the packet and clean the memory 
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(tcpPort);
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

    std::string localIP = getLocalIPv4(interface);
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
    tcph->dest = htons(tcpPort);
    tcph->seq = htonl(rand());
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(65535);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // Construct pseudo-header for TCP checksum
    struct PseudoHeader psh;
    psh.src_addr = iph->saddr;
    psh.dest_addr = iph->daddr;
    psh.reserved = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    char pseudo_packet[sizeof(PseudoHeader) + sizeof(struct tcphdr)];
    memcpy(pseudo_packet, &psh, sizeof(PseudoHeader));
    memcpy(pseudo_packet + sizeof(PseudoHeader), tcph, sizeof(struct tcphdr));
    tcph->check = checksum(pseudo_packet, sizeof(pseudo_packet));

    // Send packet
    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        std::cerr << "Packet send failed (TCP IPv4). errno: " << errno << std::endl;
        close(sock);
        return 1;
    }

    close(sock);

    return TCP_recieve_packet_v4(interface, destAddr4, timeout, tcpPort);
}
