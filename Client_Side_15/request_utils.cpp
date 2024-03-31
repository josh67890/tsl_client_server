#include <string>
#include <vector>
#include "structs.h"
#include "request_utils.h"
#include "size.h"
#include "codes.h"
#include <stdexcept>
#include "client_utils.h"

#define VERSION (unsigned char) 3
//std::vector<unsigned char> requests::string_To_Utf8_Bytes(const std::wstring& str){}
std::string requests::bytes_to_string(const std::vector<unsigned char>& bytes) {
	// Construct a string from the byte sequence
	return std::string(bytes.begin(), bytes.end());
}


std::vector<unsigned char> requests::extract_byte_range(const std::vector<unsigned char>& bytes, int start, int end) {
	// Extract bytes in the specified range
	return std::vector<unsigned char>(bytes.begin() + start, bytes.begin() + end);
}


std::vector<unsigned char> requests::string_To_Bytes(const std::string& str) {
	std::vector<unsigned char> bytes;

	// Copy characters from string to bytes
	for (char ch : str) {
		bytes.push_back(static_cast<unsigned char>(ch));
	}

	return bytes;
}


std::vector<unsigned char> requests::get_little_endian_bytes(const int value, int byte_size){
	std::vector<unsigned char> bytes;

	for (int i = 0; i < byte_size; ++i) {
		unsigned char byte = (value >> (8 * i)) & 0xFF;
		bytes.push_back(byte);
	}

	return bytes;
}


int requests::convert_from_little_endian_bytes(const std::vector<unsigned char> &value, int byte_size) {
	int result = 0;
	for (int i = 0; i < byte_size; i++)
		result |= static_cast<int>(value[i]) << (i * 8);
	return result;
}


std::vector<unsigned char> requests::construct_client_header(const structs::client_info& info, int request_code, int _payload_size){
	std::vector<unsigned char> header;

	std::vector<unsigned char> id = info.uuid;
	std::vector<unsigned char> code = get_little_endian_bytes(request_code, size::code_no);
	std::vector<unsigned char> payload_size = get_little_endian_bytes(_payload_size, size::payload);

	header.insert(header.end(), id.begin(), id.end());
	header.push_back(VERSION);
	header.insert(header.end(), code.begin(), code.end());
	header.insert(header.end(), payload_size.begin(), payload_size.end());

	return header;
}

#define INSERT payload.insert(payload.end(), bytes_vector.begin(), bytes_vector.end()); bytes_vector.clear();
std::vector<unsigned char> requests::construct_request(const structs::client_info& info, int request_code){
	std::vector<unsigned char> payload;
	std::vector<unsigned char> bytes_vector;
	switch (request_code)
	{
	/*case  codes::cl_reg: case codes::client_reconn:*/
	case 1025: case 1027:
		bytes_vector = string_To_Bytes(info.name);
		bytes_vector.resize(size::name_block, 0);
		INSERT
		break;

	case 1026:
		bytes_vector = string_To_Bytes(info.name);
		bytes_vector.resize(size::name_block, 0);
		INSERT
		bytes_vector = info.keys->public_key;
		INSERT
		break;

	case 1028:
		bytes_vector = get_little_endian_bytes( info.file_info->encrypted_size, size::contents);
		/*payload.insert(payload.end(), bytes_vector.begin(), bytes_vector.end())*/
		INSERT
		bytes_vector = get_little_endian_bytes(info.file_info->original_size, size::contents);
		INSERT
		bytes_vector = get_little_endian_bytes(info.file_info->pack_no, size::pack_no);
		INSERT
		bytes_vector = get_little_endian_bytes(info.file_info->total_packs, size::pack_count_total);
		INSERT
		bytes_vector = string_To_Bytes(info.file_info->filename);
		bytes_vector.resize(size::filename, 0);
		INSERT
		bytes_vector = info.file_info->encrypted_data;
		INSERT
		break;


	case 1029: case 1030: case 1031:
		bytes_vector = string_To_Bytes(info.file_info->filename);
		bytes_vector.resize(size::name_max);
		INSERT
		break;
	default:
		break;
	}

	std::vector<unsigned char> header = construct_client_header(info, request_code, (int)payload.size());
	payload.insert(payload.begin(), header.begin(), header.end());
	payload.resize(size::pack, 0); // pads the packet with null bytes to be exactly size::pack size
	return payload;
}
#undef INSERT

structs::response_info requests::unpack_server_header(const std::vector<unsigned char>& header){
	structs::response_info header_info;
	int offset = 1;
	header_info.version = header[0];
	header_info.code = convert_from_little_endian_bytes(extract_byte_range(header, offset, offset+size::code_no),size::code_no);
	offset += size::code_no;
	header_info.payload_size = convert_from_little_endian_bytes(extract_byte_range(header, offset, offset + size::payload), size::payload);
	return header_info;
}


structs::response_data requests::unpack_server_response(const std::vector<unsigned char>& _payload){

	std::vector<unsigned char> header = extract_byte_range(_payload, 0, size::server_header);
	std::vector<unsigned char > payload = extract_byte_range(_payload, size::server_header, size::pack);

	structs::response_info header_info = unpack_server_header(header);
	structs::response_data data;
	data.code = header_info.code;

	int offset;

	switch (header_info.code)
	{
	case 1600: case 1604: case 1606:
		data.id = client_utils::bytes_to_hex_string(extract_byte_range(payload, 0, size::id_size));
		break;
	case 1602: case 1605:
		data.id = client_utils::bytes_to_hex_string(extract_byte_range(payload, 0, size::id_size));
		data.encrypted_aes_key = extract_byte_range(payload, size::id_size, header_info.payload_size);
		break;
	case 1603:
		data.id = client_utils::bytes_to_hex_string(extract_byte_range(payload, 0, size::id_size));
		offset = size::id_size;
		data.content_size = convert_from_little_endian_bytes(extract_byte_range(payload, offset, offset + size::contents), size::contents);
		offset += size::contents;
		data.filename = bytes_to_string(extract_byte_range(payload, offset, offset + size::filename));
		offset += size::filename;
		data.crc = convert_from_little_endian_bytes(extract_byte_range(payload, offset, offset + size::crc), size::crc);
		break;
	default:
		throw std::runtime_error("invalid response from server");
		break;
	}

	return data;

}