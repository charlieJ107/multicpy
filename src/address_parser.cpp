// AddressParser.cpp
#include "address_parser.hpp"
#include <stdexcept>
#include <iostream>

AddressParser::AddressParser(int argc, char** argv) : verify(false) {
    parseArguments(argc, argv);
}

void AddressParser::parseArguments(int argc, char** argv) {
    if (argc < 3) {
        throw std::invalid_argument("Usage: multicpy <source> <destination> [--verify]");
    }

    sourcePath = argv[1];
    destinationPath = argv[2];

    if (argc == 4 && std::string(argv[3]) == "--verify") {
        verify = true;
    }
}

std::string AddressParser::getSourcePath() const {
    return sourcePath;
}

std::string AddressParser::getDestinationPath() const {
    return destinationPath;
}

bool AddressParser::isVerifyEnabled() const {
    return verify;
}