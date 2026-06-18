#pragma once

#include <string>
#include <cstdint>
#include "PacketCapture.h"

//Informazioni estratte da un pacchetto analizzato
struct PacketInfo{
    //Layer 2
    std::string srcMac;
    std::string dstMac;

    //Layer 3
    std::string srcIp;
    std::string dstIp;
    uint8_t protocol; //6=TCP, 17=UDP, 1=ICMP

    //Layer 4
    uint16_t srcPort;
    uint16_t dstPort;

    //TCP flags
    bool synFlag;
    bool ackFlag;
    bool finFlag;
    bool rstFlag;

    //Metadata
    int length;
    struct timeval timestamp;
};

class PacketAnalyzer{
    public:
        //Analizza un pacchetto grezzo e restituisce le info estratte
        static PacketInfo analyze(const Packet& packet);

    private:
        static std::string macToString(const u_char* mac);
        static std::string ipToString(uint32_t ip);
};