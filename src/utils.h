// utils.h
#ifndef UTILS_H
#define UTILS_H

#include <vector>
#include <string>
#include <arpa/inet.h>

int parseArguments(int argc, char* argv[], std::string& interface, std::string& target, std::vector<int>& tcpPorts, std::vector<int>& udpPorts, int& timeout);
void listInterfaces();
std::vector<int> parsePorts(const std::string& portsStr);
bool resolveTarget(const std::string &target, sockaddr_in &destAddr4, sockaddr_in6 &destAddr6);

#endif // UTILS_H
