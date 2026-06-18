#include "AlertManager.h"
#include <iostream>
#include <fstream>
#include <ctime>
#include <iomanip>

// ── Utility: timestamp leggibile ─────────────────────────

static std::string currentTimestamp() {
    std::time_t now = std::time(nullptr);
    std::tm* tm_info = std::localtime(&now);
    std::ostringstream oss;
    oss << std::put_time(tm_info, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

// ── ConsoleAlertListener ──────────────────────────────────

void ConsoleAlertListener::onAlert(const AlertInfo& alert) {
    std::cout << "[ALERT] " << currentTimestamp()
              << " | " << alert.ruleName
              << " | " << alert.srcIp << ":" << alert.srcPort
              << " -> " << alert.dstIp << ":" << alert.dstPort
              << " | " << alert.message
              << std::endl;
}

// ── FileAlertListener ─────────────────────────────────────

FileAlertListener::FileAlertListener(const std::string& filename)
    : filename_(filename) {
}

void FileAlertListener::onAlert(const AlertInfo& alert) {
    std::ofstream file(filename_, std::ios::app);
    if (!file.is_open()) {
        std::cerr << "Errore: impossibile aprire il file di log." << std::endl;
        return;
    }
    file << "[ALERT] " << currentTimestamp()
         << " | " << alert.ruleName
         << " | " << alert.srcIp << ":" << alert.srcPort
         << " -> " << alert.dstIp << ":" << alert.dstPort
         << " | " << alert.message
         << std::endl;
}

// ── AlertManager ──────────────────────────────────────────

void AlertManager::addListener(std::shared_ptr<IAlertListener> listener) {
    listeners_.push_back(listener);
}

void AlertManager::dispatch(const AlertInfo& alert) {
    for (auto& listener : listeners_) {
        listener->onAlert(alert);
    }
}