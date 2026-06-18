#pragma once

#include <string>
#include <functional>
#include <pcap.h>

//Struttura che rappresenta un pacchetto catturato
struct Packet{
    const u_char* data;
    int length;
    struct timeval timestamp;
};

class PacketCapture{
    public:
        explicit PacketCapture(const std::string& interface);
        ~PacketCapture();

        //Avvia la cattura, chiama il callback per ogni pacchetto catturato
        void start(std::function<void(const Packet&)> callback);

        //Ferma la cattura
        void stop();

        //Elenca le interfacce disponibili
        static void listInterfaces();

    private:
        std::string interface_;
        pcap_t* handle_;
        bool running_;
};