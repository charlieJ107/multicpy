// FileCopier.cpp
#include "file_copier.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>

namespace fs = std::filesystem;

void FileCopier::copyFile(const std::string& source, const std::string& destination) {
    try {
        fs::path src(source);
        fs::path dest(destination);

        // 创建临时文件进行复制
        fs::path temp = dest;
        temp += ".tmp";

        std::ifstream srcFile(source, std::ios::binary);
        std::ofstream destFile(temp, std::ios::binary);

        destFile << srcFile.rdbuf();

        srcFile.close();
        destFile.close();

        // 将临时文件重命名为目标文件
        fs::rename(temp, dest);

    } catch (const std::exception& e) {
        std::cerr << "Error copying file: " << e.what() << std::endl;
        throw;
    }
}