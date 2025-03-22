/*
    VUT FIT IPK
    1. Project - L4 Scanner
    Author: Jakub Lůčný (xlucnyj00)
    Date: 2025-03-16
*/

#include <cstring>  // memcpy
#include <cstdint>

/*
    Function to calculate checksum for packets
    From: https://datatracker.ietf.org/doc/html/rfc1071#section-4.1
    Used function documented in RFC 1071, rewritten into C++ from C
*/
uint16_t checksum(void *buffer, int count) {
    uint32_t sum = 0;
    uint16_t *ptr = static_cast<uint16_t *>(buffer);

    while (count > 1) {
        sum += *ptr++;
        count -= 2;
    }
    if (count == 1) {
        sum += *(reinterpret_cast<uint8_t *>(ptr));
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}

/*
    Helper function to calculate checksum for packets using IPv6
*/
uint16_t calculate_tcp_checksum(void *tcp_header, int tcp_length, void *pseudo_header, int pseudo_length) {
    char buffer[pseudo_length + tcp_length];
    memcpy(buffer, pseudo_header, pseudo_length);
    memcpy(buffer + pseudo_length, tcp_header, tcp_length);
    return checksum(buffer, sizeof(buffer));
}