#pragma once

#include <vector>
#include <memory>
#include <string>
#include "RuleEngine.h"

//Interfaccia base per tutti i listener di alert(Observer pattern)
class IAlertListener{
    public:
        virtual ~IAlertListener() = default;
        virtual void onAlert(const AlertInfo& alert) = 0;
};

//Listener che stampa gli alert sulla console
class ConsoleAlertListener : public IAlertListener{
    public:
        void onAlert(const AlertInfo& alert) override;
};

//Listener che scrive gli alert su file di log
class FileAlertListener : public IAlertListener{
    public:
        explicit FileAlertListener(const std::string& filename);
        void onAlert(const AlertInfo& alert) override;

    private:
        std::string filename_;
};

//Gestisce la lista di listener e dispatcha gli alert(Observer pattern)
class AlertManager{
    public:
        void addListener(std::shared_ptr<IAlertListener> listener);
        void dispatch(const AlertInfo& alert);

    private:
        std::vector<std::shared_ptr<IAlertListener>> listeners_;   
};