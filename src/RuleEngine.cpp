#include "RuleEngine.h"
#include <unordered_map>

//SynFllodRule implementation
SynFloodRule::SynFloodRule(int threshold) : threshold_(threshold) {}

bool SynFloodRule::evaluate(const PacketInfo& packet){
    if(packet.protocol != 6)
        return false; //solo TCP
    
    if(!packet.synFlag || packet.ackFlag)
        return false; //solo SYN senza ACK

    synCount_[packet.srcIp]++;
    return synCount_[packet.srcIp] >= threshold_;
}

AlertInfo SynFloodRule::getAlert(const PacketInfo& packet){
    AlertInfo alert;
    alert.ruleName = getName();
    alert.srcIp = packet.srcIp;
    alert.dstIp = packet.dstIp;
    alert.srcPort = packet.srcPort;
    alert.dstPort = packet.dstPort;
    alert.message = "SYN flood detected from " + packet.srcIp;
    return alert;
}

std::string SynFloodRule::getName() const{
    return "SYN Flood Detection";
}

//IcmpFloodRule implementation
IcmpFloodRule::IcmpFloodRule(int threshold)
    : threshold_(threshold) {
}

bool IcmpFloodRule::evaluate(const PacketInfo& packet) {
    if (packet.protocol != 1) return false;  // solo ICMP

    icmpCount_[packet.srcIp]++;
    return icmpCount_[packet.srcIp] >= threshold_;
}

AlertInfo IcmpFloodRule::getAlert(const PacketInfo& packet) {
    AlertInfo alert;
    alert.ruleName = getName();
    alert.srcIp = packet.srcIp;
    alert.dstIp = packet.dstIp;
    alert.srcPort = 0;
    alert.dstPort = 0;
    alert.message = "ICMP flood rilevato da " + packet.srcIp +
                    " (" + std::to_string(icmpCount_[packet.srcIp]) + " pacchetti ICMP)";
    return alert;
}

std::string IcmpFloodRule::getName() const {
    return "ICMP Flood Detection";
}

// ── RuleEngine ────────────────────────────────────────────

void RuleEngine::addRule(std::shared_ptr<IRule> rule) {
    rules.push_back(rule);
}

std::vector<AlertInfo> RuleEngine::evaluate(const PacketInfo& packet) {
    std::vector<AlertInfo> alerts;

    for (auto& rule : rules) {
        if (rule->evaluate(packet)) {
            alerts.push_back(rule->getAlert(packet));
        }
    }

    return alerts;
}