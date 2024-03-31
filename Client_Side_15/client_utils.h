//#pragma once
//#include <vector>
//#include <string>
//#include "structs.h"
//class client_utils {
//private:
//	std::vector<unsigned char> hexStringToBytes(const std::string& hex);
//	std::vector<unsigned char> base64Decode(const std::string& base64);
//public:
//
//	structs::transfer_info get_data_from_transfer_info(const std::string& filename);
//	structs::me_info get_data_from_me_info(const std::string& filename);
//};

// client_utils.h
#pragma once

#ifndef UTIL_FUNCTIONS_H
#define UTIL_FUNCTIONS_H

#include <vector>
#include <string>
#include "structs.h"

class client_utils {
private:
    static std::string base64;
    static std::vector<unsigned char> base64Decode(const std::string& base64);
    static std::string base64_encode(const std::vector<unsigned char> bytes);
    static std::string stripWhitespace(const std::string& str);
public:
    static std::vector<unsigned char> hexStringToBytes(const std::string& hex);
    static std::string bytes_to_hex_string(const std::vector<unsigned char>& bytes);
    static void get_data_from_transfer_info(const std::string& filename, structs::client_info& info);
    static void get_data_from_me_info(const std::string& filename, structs::client_info& info);
    static void save_client_data_to_me_info(const std::string& filename, const structs::client_info& info,const structs::response_data& response, const structs::keys & keys);
    static void save_rsa_pair_to_priv_key(const std::string& filename, const structs::keys &keys);
    static structs::keys read_keys_from_priv_key(const std::string& filename);
    
};

#endif // UTIL_FUNCTIONS_H
