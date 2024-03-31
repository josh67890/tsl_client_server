
#include <iostream>
#include <fstream>
#include <string>
#include <iostream>
#include <sstream>

#include "structs.h"
#include "client_utils.h"
#include <iomanip>


std::string client_utils::base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// function to strip a string from whitespace
std::string client_utils::stripWhitespace(const std::string& str) {
    // Find the first non-whitespace character
    size_t start = str.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) {
        // If the string is all whitespace, return an empty string
        return "";
    }

    // Find the last non-whitespace character
    size_t end = str.find_last_not_of(" \t\n\r");

    // Return the substring containing non-whitespace characters
    return str.substr(start, end - start + 1);
}

// Function to convert a hexadecimal string to bytes
std::vector<unsigned char> client_utils::hexStringToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        // Convert two hexadecimal characters to a byte
        unsigned char byte = std::stoi(hex.substr(i, 2), nullptr, 16);
        // Add the byte to the vector
        bytes.push_back(byte);
    }
    return bytes;
}

std::string client_utils::bytes_to_hex_string(const std::vector<unsigned char>& bytes){
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto& byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

// Function to decode a Base64 encoded string into bytes
std::vector<unsigned char> client_utils::base64Decode(const std::string& base64) {

    // Vector to store decoded bytes
    std::vector<unsigned char> decoded;
    // Variables to keep track of bits and accumulator
    int bits_collected = 0;
    unsigned int accumulator = 0;

    // Loop through each character in the Base64 string
    for (char c : base64) {
        // Skip whitespace characters
        if (std::isspace(c)) {
            continue;
        }
        // Find the index of the character in the Base64 character set
        const size_t index = base64.find(c);
        // If the character is not found, break the loop
        if (index == std::string::npos) {
            break;
        }
        // Shift the accumulator and add the index
        accumulator = (accumulator << 6) | index;
        bits_collected += 6;
        // If 8 bits are collected, add a byte to the decoded vector
        if (bits_collected >= 8) {
            bits_collected -= 8;
            decoded.push_back((accumulator >> bits_collected) & 0xFF);
        }
    }

    return decoded;
}

std::string client_utils::base64_encode(const std::vector<unsigned char> bytes) {
    std::string encoded;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    for (const auto& byte : bytes) {
        char_array_3[i++] = byte;
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                encoded += base64[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            encoded += base64[char_array_4[j]];

        while ((i++ < 3))
            encoded += '=';
    }

    return encoded;
}

void client_utils::get_data_from_transfer_info(const std::string& filename, structs::client_info& info) {
 
    try {
        std::ifstream file(filename);
        if (file.is_open()) {
            std::string line;
            int lineCount = 0;
            while (std::getline(file, line) && lineCount < 3 && !(line = stripWhitespace(line)).empty()) {
                std::istringstream iss(line);
                switch (lineCount) {
                case 0:
                    std::getline(iss, info.host, ':');
                    std::getline(iss, info.port);
                    break;
                case 1:
                    std::getline(iss, info.name);
                    break;
                case 2:
                    std::getline(iss, info.file_info->filename);
                    break;
                }
                lineCount++;
            }
            file.close();
            if (lineCount < 3) {
                throw std::runtime_error("missing fields in me.info\n");
            }
        }
        else {
            std::cerr << "Unable to open file: " << filename << std::endl;
        }

    }

    catch (std::runtime_error& e) {
        std::cout << "error while parsing file\n"<<e.what()<<'\n';
    }

}

void client_utils::get_data_from_me_info(const std::string& filename, structs::client_info& info){
    try {
        std::ifstream file(filename);
        if (file.is_open()) {
            std::string line;
            int lineCount = 0;
            while (std::getline(file, line) && lineCount < 3 && !(line = stripWhitespace(line)).empty()) {
                switch (lineCount) {
                case 0:
                    info.name = line;
                    break;
                case 1:
                    info.uuid = hexStringToBytes(line);
                    break;
                case 2:
                    info.private_key = base64Decode(line);
                    break;
                }
                lineCount++;
            }
            file.close();
            if (lineCount < 3) {
                throw std::runtime_error("missing fields in me.info\n");
            }
        }
        else {
            std::cerr << "Unable to open file: " << filename << std::endl;
            info.uuid = std::vector<unsigned char>(16, 0); // initializes uuid to zero if not registered
        }
    }
    catch (std::runtime_error& e) {
        std::cerr << "error while parsing file\nsending registration request based on file 'transfer.info'"<<e.what()<<'\n';
    }


}

void client_utils::save_client_data_to_me_info(const std::string& filename, const structs::client_info& info, const structs::response_data& response, const structs::keys& keys){
 
    // Open the file
    std::ofstream me_file(filename);
    if (!me_file.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return;
    }

    //encode private key as base64
    std::string encoded_key = client_utils::base64_encode(keys.private_key); 

    me_file << info.name << std::endl;
    me_file << response.id << std::endl;
    me_file << encoded_key << std::endl;

    me_file.close();
   
}

void client_utils::save_rsa_pair_to_priv_key(const std::string& filename, const structs::keys &keys){ // saves the keys as hex_strings

    std::ofstream key_file(filename);
    if (!key_file.is_open()) {
        throw std::runtime_error("error while saving keys to key_file");
    }

    key_file << bytes_to_hex_string(keys.private_key) << std::endl;
    key_file << bytes_to_hex_string(keys.public_key) << std::endl;

    key_file.close();

}

structs::keys client_utils::read_keys_from_priv_key(const std::string& filename) {
    structs::keys keys;
    try {
        std::ifstream key_file(filename);
        if (!key_file.is_open()) {
            throw std::runtime_error("error while reading keys from key_file");
        }
        std::string private_key;
        std::string public_key;
        std::getline(key_file, private_key);
        std::getline(key_file, public_key);


        keys.private_key = hexStringToBytes(private_key);
        keys.public_key = hexStringToBytes(public_key);
        return keys;
    }
    catch (std::runtime_error& e) {
        std::cerr << e.what() << '\n';
        return keys;
    }

}

