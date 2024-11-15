// recovery_manager.cpp - Implementation of RecoveryManager class

#include "recovery_manager.hpp"
#include <fstream>

void RecoveryManager::saveProgress(const std::string& task) {
    std::ofstream recoveryFile(".multicpy_record", std::ios::app);
    recoveryFile << task << std::endl;
}

void RecoveryManager::loadProgress() {
    std::ifstream recoveryFile(".multicpy_record");
    std::string task;
    while (std::getline(recoveryFile, task)) {
        // 继续处理剩余的任务
    }
}

void RecoveryManager::removeRecoveryFile() {
    std::remove(".multicpy_record");
}