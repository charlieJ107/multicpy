// HashVerifier.cpp
#include "hash_verifier.hpp"
#include <openssl/sha.h>
#include <fstream>
#include <iomanip>
#include <sstream>

std::string HashVerifier::calculateHash(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) throw std::runtime_error("Unable to open file for hashing");

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer))) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }
    SHA256_Update(&sha256, buffer, file.gcount());

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    std::ostringstream result;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        result << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return result.str();
}

bool HashVerifier::verifyFile(const std::string& source, const std::string& destination) {
    std::string sourceHash = calculateHash(source);
    std::string destHash = calculateHash(destination);
    return sourceHash == destHash;
}