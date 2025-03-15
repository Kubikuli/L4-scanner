#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <cerrno>

#include <net/if.h>
#include <sys/ioctl.h> // For ioctl


// UDP port scanning function
int UDP_scan_v4(int udpPort, const sockaddr_in& destAddr, const std::string& interface) {
    // Create local copy and set port
    sockaddr_in tmpAddr = destAddr;
    tmpAddr.sin_port = htons(udpPort);

    // Create non-blocking UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (sock <= 0) {
        perror("Socket creation failed");
        return 1;
    }

    // Specify interface to use
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface.c_str(), interface.length()) < 0) {
        perror("setsockopt SO_BINDTODEVICE failed");
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&tmpAddr, sizeof(tmpAddr)) < 0 && errno != EINPROGRESS) {
        perror("Connect failed");
        close(sock);
        return 1;
    }

    // Send a small packet
    const char data[] = "a";
    if (send(sock, data, sizeof(data), 0) < 0) {
        perror("Send failed");
        close(sock);
        return 1;
    }

    // Set up epoll
    int epfd = epoll_create1(0);
    struct epoll_event ev, events[1];
    ev.events = EPOLLERR | EPOLLIN;
    ev.data.fd = sock;
    epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);

    // Wait for an event
    int nfds = epoll_wait(epfd, events, 1, 2000); // 2s timeout for example
    if (nfds > 0) {
        if (events[0].events & EPOLLERR) {
            int err = 0; socklen_t len = sizeof(err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err == ECONNREFUSED) {
                std::cout << inet_ntoa(tmpAddr.sin_addr) << " " << udpPort << " udp closed" << std::endl;
            }
        }
    }
    // else no response => possibly open or filtered
    else{
        std::cout << inet_ntoa(tmpAddr.sin_addr) << " " << udpPort << " udp open" << std::endl;
    }

    close(epfd);
    close(sock);
    return 0;
}

int UDP_scan_v6(int udpPort, const sockaddr_in6& destAddr6, const std::string& interface) {
    sockaddr_in6 tmpAddr6 = destAddr6;
    tmpAddr6.sin6_port = htons(udpPort);

    // Create non-blocking UDP socket
    int sock = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (sock <= 0) {
        perror("Socket creation failed");
        return 1;
    }

    // Specify interface to use
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface.c_str(), interface.length()) < 0) {
        perror("setsockopt SO_BINDTODEVICE failed");
        close(sock);
        return 1;
    }

    // Connect
    if (connect(sock, (struct sockaddr *)&tmpAddr6, sizeof(tmpAddr6)) < 0 && errno != EINPROGRESS) {
        perror("Connect failed");
        close(sock);
        return 1;
    }

    // Send a small packet
    const char data[] = "a";
    if (send(sock, data, sizeof(data), 0) < 0) {
        perror("Send failed");
        close(sock);
        return 1;
    }

    // Set up epoll
    int epfd = epoll_create1(0);
    struct epoll_event ev, events[1];
    ev.events = EPOLLERR | EPOLLIN;
    ev.data.fd = sock;
    epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);

    // Wait for an event
    int nfds = epoll_wait(epfd, events, 1, 2000); // 2s timeout
    char ipStr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &tmpAddr6.sin6_addr, ipStr, INET6_ADDRSTRLEN);

    if (nfds > 0) {
        if (events[0].events & EPOLLERR) {
            int err = 0; socklen_t len = sizeof(err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err == ECONNREFUSED) {
                std::cout << ipStr << " " << udpPort << " udp closed" << std::endl;
            }
        }
    } else {
        std::cout << ipStr << " " << udpPort << " udp open" << std::endl;
    }

    close(epfd);
    close(sock);
    return 0;
}
