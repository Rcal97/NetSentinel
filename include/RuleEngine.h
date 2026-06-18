#pragma once

#include <vector>
#include <memory>
#include <string>
#include "PacketAnalyzer.h"

//Risultato della valutazione di una regola
struct AlertInfo{
    std::string ruleName;
    std::string srcIp;
    std::string dstIp;
    uint16_t srcPort;
    uint16_t dstPort;
    std::string message;
};

//Interfaccia base per tutte le regole (Strategy pattern)
class IRule{
    public:
    virtual ~IRule() = default;
    virtual bool evaluate(const PacketInfo& packet) = 0;
    virtual AlertInfo getAlert(const PacketInfo& packet) = 0;
    virtual std::string getName() const = 0;
};

//Regola: rivela SYN flood
class SynFloodRule : public IRule{
    public:
        explicit SynFloodRule(int threshold = 100);
        bool evaluate(const PacketInfo& packet) override;
        AlertInfo getAlert(const PacketInfo& packet) override;
        std::string getName() const override;

    private:
        int threshold_;
        std::unordered_map<std::string, int> synCount_;
};

//Regola: rivela ICMP flood
class IcmpFloodRule : public IRule{
    public:
        explicit IcmpFloodRule(int threshold = 50);
        bool evaluate(const PacketInfo& packet) override;
        AlertInfo getAlert(const PacketInfo& packet) override;
        std::string getName() const override;

    private:
        int threshold_;
        std::unordered_map<std::string, int> icmpCount_;
};

//Motore che applica tutte le regole ad ogni pacchetto
class RuleEngine{
    public:
        void addRule(std::shared_ptr<IRule> rule);
        std::vector<AlertInfo> evaluate(const PacketInfo& packet);

    private:
        std::vector<std::shared_ptr<IRule>> rules;
};