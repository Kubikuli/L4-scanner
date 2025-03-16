/*
    VUT FIT IPK
    1. Project - L4 Scanner
    Author: Jakub Lůčný (xlucnyj00)
    Date: 2025-03-16
*/

#ifndef UTILS_H
#define UTILS_H

#include <vector>
#include <string>
#include <arpa/inet.h>

// Function to parse arguments from the command line and get their values
// Returns 0 if successful, 1 if list of available interfaces was requested
int parseArguments(int argc, char* argv[], std::string& interface, std::string& target, std::vector<int>& tcpPorts, std::vector<int>& udpPorts, int& timeout);

// Prints out a list of available network interfaces
void listInterfaces();

// Function that takes string containing a ipv4 or ipv6 address or hostname
// and resolves it to a sockaddr_in or sockaddr_in6 structure
// Returns true if target is ipv6, false if ipv4
bool resolveTarget(const std::string &target, sockaddr_in &destAddr4, sockaddr_in6 &destAddr6);

#endif // UTILS_H
