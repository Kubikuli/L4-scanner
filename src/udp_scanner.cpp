/*
    VUT FIT IPK
    1. Project - L4 Scanner
    Author: Jakub Lůčný (xlucnyj00)
    Date: 2025-03-16
*/

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <cerrno>
#include <mutex>
#include <net/if.h>

#include "udp_scanner.h"

// Lock for printing correctly
std::mutex UDPScanner::printMutex;

/*
    Main public method to scan a port using UDP for IPv4 address
    Takes port number and destination address as arguments
    Uses epoll to wait for a response
    If no response is received, the port is considered open
*/
int UDPScanner::scanV4(int port, const sockaddr_in& destAddr) {
    // Create local copy of destination address and set dest port
    sockaddr_in tmpAddr = destAddr;
    tmpAddr.sin_port = htons(port);

    // Create non-blocking UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (sock <= 0) {
        std::cerr << "Socket creation failed (UDP IPv4)\n";
        return 1;
    }

    // Specify interface to use
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface_.c_str(), interface_.length()) < 0) {
        std::cerr << "Failed to set socket options (UDP IPv4)\n";
        close(sock);
        return 1;
    }

    // Try to connect to the destination address
    if (connect(sock, (struct sockaddr *)&tmpAddr, sizeof(tmpAddr)) < 0 && errno != EINPROGRESS) {
        std::cerr << "Connection to destination failed (UDP IPv4)\n";
        close(sock);
        return 1;
    }

    // Send a packet
    const char data[] = "s";
    if (send(sock, data, sizeof(data), 0) < 0) {
        std::cerr << "Sending packet failed (UDP IPv4)\n";
        close(sock);
        return 1;
    }

    // Set up epoll to capture packets
    int epfd = epoll_create1(0);
    struct epoll_event ev, events[1];
    ev.events = EPOLLERR | EPOLLIN;
    ev.data.fd = sock;
    epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);

    // Wait for an event
    int nfds = epoll_wait(epfd, events, 1, timeout_);

    // Response received
    if (nfds > 0) {
        if (events[0].events & EPOLLERR) {
            int err = 0;
            socklen_t len = sizeof(err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err == ECONNREFUSED) {
                std::lock_guard<std::mutex> lock(printMutex);
                std::cout << inet_ntoa(tmpAddr.sin_addr) << " " << port << " udp closed" << std::endl;
            }
        }
    }
    // No response -> port is open or filtered
    else {
        std::lock_guard<std::mutex> lock(printMutex);
        std::cout << inet_ntoa(tmpAddr.sin_addr) << " " << port << " udp open" << std::endl;
    }

    close(epfd);
    close(sock);
    return 0;
}

/*
    Main public function to scan a port using UDP for IPv6 address
    Same as scanV4 but for IPv6
    Takes port number and destination address as arguments
    Uses epoll to wait for a response
    If no response is received, the port is considered open
*/
int UDPScanner::scanV6(int port, const sockaddr_in6& destAddr6) {
    // Create local copy of destination address and set dest port
    sockaddr_in6 tmpAddr6 = destAddr6;
    tmpAddr6.sin6_port = htons(port);

    // Create non-blocking UDP socket
    int sock = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (sock <= 0) {
        std::cerr << "Socket creation failed (UDP IPv6)\n";
        return 1;
    }

    // Specify interface to use
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface_.c_str(), interface_.length()) < 0) {
        std::cerr << "Failed to set socket options (UDP IPv6)\n";
        close(sock);
        return 1;
    }

    // Try to connect to the destination address
    if (connect(sock, (struct sockaddr *)&tmpAddr6, sizeof(tmpAddr6)) < 0 && errno != EINPROGRESS) {
        std::cerr << "Connection to destination failed (UDP IPv6)\n";
        close(sock);
        return 1;
    }

    // Send a packet
    const char data[] = "s";
    if (send(sock, data, sizeof(data), 0) < 0) {
        std::cerr << "Sending packet failed (UDP IPv6)\n";
        close(sock);
        return 1;
    }

    // Set up epoll to capture packets
    int epfd = epoll_create1(0);
    struct epoll_event ev, events[1];
    ev.events = EPOLLERR | EPOLLIN;
    ev.data.fd = sock;
    epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);

    // Wait for an event
    int nfds = epoll_wait(epfd, events, 1, timeout_); // timeout
    // Get string representation of the IP address
    char ipStr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &tmpAddr6.sin6_addr, ipStr, INET6_ADDRSTRLEN);

    // Response received
    if (nfds > 0) {
        if (events[0].events & EPOLLERR) {
            int err = 0; socklen_t len = sizeof(err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err == ECONNREFUSED) {
                std::lock_guard<std::mutex> lock(printMutex);
                std::cout << ipStr << " " << port << " udp closed" << std::endl;
            }
        }
    }
    // No response -> port is open or filtered
    else {
        std::lock_guard<std::mutex> lock(printMutex);
        std::cout << ipStr << " " << port << " udp open" << std::endl;
    }

    close(epfd);
    close(sock);
    return 0;
}
