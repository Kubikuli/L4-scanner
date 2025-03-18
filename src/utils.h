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

// Function that takes string containing a IPv4 or IPv6 address or hostname,
// if it's hostname, DNS resolves it and returns vector of resolved addresses 
// Returns string vector of destination addresses
std::vector<std::string> resolveTarget(const std::string &target);

#endif // UTILS_H
