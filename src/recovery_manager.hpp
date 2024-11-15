// RecoveryManager.h
#ifndef RECOVERY_MANAGER_H
#define RECOVERY_MANAGER_H

#include <string>

class RecoveryManager {
public:
    static void saveProgress(const std::string& task);
    static void loadProgress();
    static void removeRecoveryFile();
};

#endif // RECOVERY_MANAGER_H