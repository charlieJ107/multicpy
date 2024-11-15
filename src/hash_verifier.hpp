// HashVerifier.h
#ifndef HASH_VERIFIER_H
#define HASH_VERIFIER_H

#include <string>

class HashVerifier {
public:
    static std::string calculateHash(const std::string& filepath);
    static bool verifyFile(const std::string& source, const std::string& destination);
};

#endif // HASH_VERIFIER_H