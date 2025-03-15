#ifndef SCANNER_H
#define SCANNER_H

#include <string>
#include <vector>

class Scanner {
public:
    Scanner(const std::string &iface, const std::string &target, 
            const std::vector<int> &tcp_ports, const std::vector<int> &udp_ports, 
            int timeout);

    void startScan();
    static void listInterfaces(); // To list available network interfaces

private:
    std::string interface;
    std::string target;
    std::vector<int> tcp_ports;
    std::vector<int> udp_ports;
    int timeout;

    void scanTCP();
    void scanUDP();
};

#endif
