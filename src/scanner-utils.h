/*
    VUT FIT IPK
    1. Project - L4 Scanner
    Author: Jakub Lůčný (xlucnyj00)
    Date: 2025-03-16
*/

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

// Pseudo-header for IPv6 checksum calculation
struct PseudoHeaderV6 {
    struct in6_addr src;
    struct in6_addr dest;
    uint32_t length;
    uint8_t zero[3];
    uint8_t nextHeader;
} __attribute__((packed));

// Struct to pass both handle and "packetArrived" flag to pcap_loop
struct PacketHandlerData {
    pcap_t* handle;
    std::atomic<bool> packetArrived;
};

// Function to calculate checksum for packets
uint16_t checksum(void *buffer, int length);

// Helper function to calculate checksum for packets using IPv6
uint16_t calculate_tcp_checksum(void *tcp_header, int tcp_length, void *pseudo_header, int pseudo_length);

#endif // SCANNER_UTILS_H
