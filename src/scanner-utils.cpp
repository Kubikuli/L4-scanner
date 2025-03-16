#include <cstring>  // memcpy
#include <cstdint>

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