#include <iostream>
#include <memory>
#include <string>
#include "PacketCapture.h"
#include "PacketAnalyzer.h"
#include "RuleEngine.h"
#include "AlertManager.h"

int main(int argc, char* argv[]){
    //Parsing argomenti
    if(argc < 2){
        std::cout << "Utilizzo: sudo ./NetSentinel -i <interfaccia>" << std::endl;
        std::cout << "          sudo ./NetSentinel --list" << std::endl;
        return 1;
    }

    std::string arg = argv[1];

    if(arg == "--list"){
        PacketCapture::listInterfaces();
        return 0;
    }

    if(arg != "-i" || argc < 3){
        std::cerr << "Argomento non valido. Usa --list per vedere le interfacce." << std::endl;
        return 1;
    }

    std::string interface = argv[2];

    //Setup AlertManager con listener console e file
    AlertManager alertManager;
    alertManager.addListener(std::make_shared<ConsoleAlertListener>());
    alertManager.addListener(std::make_shared<FileAlertListener>("alerts.log"));

    //Setup RuleEngine con regole di detection
    RuleEngine ruleEngine;
    ruleEngine.addRule(std::make_shared<SynFloodRule>(100)); //Soglia SYN flood
    ruleEngine.addRule(std::make_shared<IcmpFloodRule>(50));

    //Setup PacketCapture
    PacketCapture capture(interface);

    std::cout << "NetSentinel avviato su interfaccia: " << interface << std::endl;
    std::cout << "Premi Ctrl+C per terminare." << std::endl;

    //Callback: per ogni pacchetto catturato, analizza e valuta le regole
    capture.start([&](const Packet& packet){
        PacketInfo info = PacketAnalyzer::analyze(packet);
        std::vector<AlertInfo> alerts = ruleEngine.evaluate(info);
        for(const auto& alert : alerts){
            alertManager.dispatch(alert);
        }
    });

    return 0;
}