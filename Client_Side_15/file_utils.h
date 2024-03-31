#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <iostream>
#include <sstream>
#include <vector>
#include <string>

#include "structs.h"
#include "client_utils.h"

class file_utils {
private:



public:
	static std::vector<unsigned char> read_data_to_transmit_from_file(const std::string& filename);
	static int calculate_crc(const std::vector<unsigned char>& file_data);
	static int calculate_pack_count(int file_size);
	static  std::vector<unsigned char> get_next_chunk(const  std::vector<unsigned char>& data, int chunk_num);
};
