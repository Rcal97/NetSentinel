#include "PacketAnalyzer.h"
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>

PacketInfo PacketAnalyzer::analyze(const Packet& packet){
    PacketInfo info{};

    const u_char* data = packet.data;
    int length = packet.length;

    //Layer 2 - Ethernet header (14 byte)
    if(length < 14)
        return info;

    const struct ether_header* ethHeader = (const struct ether_header*)data;
    info.srcMac = macToString(ethHeader->ether_shost);
    info.dstMac = macToString(ethHeader->ether_dhost);

    //Controlliamo che sia un pacchetto IP
    if(ntohs(ethHeader->ether_type) != ETHERTYPE_IP)
        return info;

    //Layer 3 - IP header
    const struct ip* ipHeader = (struct ip*)(data + 14);
    info.srcIp = inet_ntoa(ipHeader->ip_src);
    info.dstIp = inet_ntoa(ipHeader->ip_dst);
    info.protocol = ipHeader->ip_p;
    info.length = length;
    info.timestamp = packet.timestamp;

    int ipHeaderLength = ipHeader->ip_hl * 4; //ip_hl è in parole da 4 byte

    //Layer 4 - TCP/UDP/ICMP
    const u_char* transport = data + 14 + ipHeaderLength;

    if(info.protocol == IPPROTO_TCP){
        const struct tcphdr* tcpHeader = (struct tcphdr*) transport;
        info.srcPort = ntohs(tcpHeader->th_sport);
        info.dstPort = ntohs(tcpHeader->th_dport);
        info.synFlag = tcpHeader->th_flags & TH_SYN;
        info.ackFlag = tcpHeader->th_flags & TH_ACK;
        info.finFlag = tcpHeader->th_flags & TH_FIN;
        info.rstFlag = tcpHeader->th_flags & TH_RST;
    }
    else if(info.protocol == IPPROTO_UDP){
        const struct udphdr* udpHeader = (struct udphdr*) transport;
        info.srcPort = ntohs(udpHeader->uh_sport);
        info.dstPort = ntohs(udpHeader->uh_dport);
    }
    else if(info.protocol == IPPROTO_ICMP){
        //ICMP non ha porte, quindi lasciamo srcPort e dstPort a 0
    }
    return info;
}

std::string PacketAnalyzer::macToString(const u_char* mac){
    std::ostringstream oss;
    for(int i=0; i<6; i++){
        if(i>0)
            oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    }
    return oss.str();
}

std::string PacketAnalyzer::ipToString(uint32_t ip){
    struct in_addr addr;
    addr.s_addr = ip;
    return inet_ntoa(addr);
}