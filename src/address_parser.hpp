// AddressParser.h
#ifndef ADDRESS_PARSER_H
#define ADDRESS_PARSER_H

#include <string>
#include <vector>

class AddressParser {
public:
    AddressParser(int argc, char** argv);

    std::string getSourcePath() const;
    std::string getDestinationPath() const;
    bool isVerifyEnabled() const;

private:
    std::string sourcePath;
    std::string destinationPath;
    bool verify;

    void parseArguments(int argc, char** argv);
};

#endif // ADDRESS_PARSER_H