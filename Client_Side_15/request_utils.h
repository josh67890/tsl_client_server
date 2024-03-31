#pragma once
#include <string>
#include <vector>
#include "structs.h"


class requests {
private:
	//static std::vector<unsigned char> string_To_Utf8_Bytes(const std::wstring& str);
	static std::string bytes_to_string(const std::vector<unsigned char>& bytes);
	static std::vector<unsigned char> extract_byte_range(const std::vector<unsigned char>& bytes, int start, int end);
	static std::vector<unsigned char> string_To_Bytes(const std::string& str);
	static std::vector<unsigned char> construct_client_header(const structs::client_info& info, int request_code, int payload_size);
	static structs::response_info unpack_server_header(const std::vector<unsigned char>& header);
	static std::vector<unsigned char> get_little_endian_bytes(const int value, int byte_size);
	static int convert_from_little_endian_bytes(const std::vector<unsigned char>& value, int byte_size);
public:
	
	static std::vector<unsigned char> construct_request(const structs::client_info& info, int request_code);
	static structs::response_data unpack_server_response(const std::vector<unsigned char>& payload);
};