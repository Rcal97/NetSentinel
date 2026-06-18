#include "PacketCapture.h"
#include <iostream>
#include <stdexcept>

PacketCapture::PacketCapture(const std::string& interface) : interface_(interface), handle_(nullptr), running_(false){

}

PacketCapture::~PacketCapture(){
    stop();
}

void PacketCapture::start(std::function<void(const Packet&)> callback) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    handle_ = pcap_open_live(
        interface_.c_str(), //nome interfaccia
        65535, //snaplen: cattura fino a 65535 byte per pacchetto
        1, //promiscuous mode: cattura tutto il traffico
        1000, //timeout in ms
        errbuf
    );

    if(handle_ == nullptr){
        throw std::runtime_error("Impossibile aprire interfaccia: " + std::string(errbuf));
    }

    running_ = true;
    struct pcap_pkthdr* header;
    const u_char* data;

    while(running_){
        int result = pcap_next_ex(handle_, &header, &data);

        if(result == 1){
            Packet packet;
            packet.data = data;
            packet.length = header->len;
            packet.timestamp = header->ts;
            callback(packet);
        }
        else if(result == -1){
            std::cerr << "Errore durante la cattura: " << pcap_geterr(handle_) << std::endl;
            break;
        }

        //result == 0: timeout scaduto, continua a catturare
    }
}

void PacketCapture::stop(){
    running_ = false;
    if(handle_ != nullptr){
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

void PacketCapture::listInterfaces(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;


    if(pcap_findalldevs(&alldevs, errbuf) == -1){
        std::cerr << "Errore: " << errbuf << std::endl;
        return;
    }

    std::cout << "Interfacce disponibili: " << std::endl;
    for(pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next){
        std::cout << " - " << dev->name;
        if(dev->description){
            std::cout << " (" << dev->description << ")";
        }
        std::cout << std::endl;
    }

    pcap_freealldevs(alldevs);
}