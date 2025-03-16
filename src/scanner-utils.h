// scanner-utils.h
#ifndef SCANNER_UTILS_H
#define SCANNER_UTILS_H

// Pseudo-header for checksum calculation
struct PseudoHeader {
    uint32_t src_addr;
    uint32_t dest_addr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_length;
};

// Create a pseudo-header struct for IPv6
struct PseudoHeaderV6 {
    struct in6_addr src;
    struct in6_addr dest;
    uint32_t length;
    uint8_t zero[3];
    uint8_t nextHeader;
} __attribute__((packed));

// A small struct to pass both handle and "packetArrived" flag to pcap_loop and its handler
struct PacketHandlerData {
    pcap_t* handle;
    std::atomic<bool> packetArrived;
};

uint16_t checksum(void *buffer, int length);
uint16_t calculate_tcp_checksum(void *tcp_header, int tcp_length, void *pseudo_header, int pseudo_length);


#endif // SCANNER_UTILS_H
