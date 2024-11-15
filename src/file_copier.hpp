// FileCopier.h
#ifndef FILE_COPIER_H
#define FILE_COPIER_H

#include <string>

class FileCopier {
public:
    static void copyFile(const std::string& source, const std::string& destination);
};

#endif // FILE_COPIER_H