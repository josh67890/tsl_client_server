
#include <iostream>
#include <fstream>
#include <string>
#include <iostream>
#include <sstream>
#include <vector>
#include <string>

#include "structs.h"
#include "file_utils.h"
#include "size.h"
#include <algorithm>

std::vector<unsigned char> file_utils::read_data_to_transmit_from_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        // File could not be opened
        std::cout << "unable to open file" << filename << '\n';
        return std::vector<unsigned char>();
    }

    // Determine the size of the file
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);\


    // Read the file into the vector
    std::vector<unsigned char> fileData(fileSize);

    if (!file.read(reinterpret_cast<char*>(fileData.data()), fileSize)) {
        // Error occurred while reading
        return std::vector<unsigned char>();
    }

    return fileData;
}
int file_utils::calculate_crc(const std::vector<unsigned char>& file_data){
    unsigned int checksum = 0;
    for (unsigned char byte : file_data) {
        checksum += byte;
    }
    return checksum;
}
int file_utils::calculate_pack_count(int file_size){
	int factor = file_size / size::file_payload;
	return (factor * size::file_payload == file_size) ? factor : factor + 1;
}
std::vector<unsigned char> file_utils::get_next_chunk(const  std::vector<unsigned char>& data, int chunk_num){
    int chunkSize = size::file_payload;

    // Calculate the starting position of the chunk
    int startPos = chunk_num * chunkSize;

    // Calculate the end position of the chunk
    int endPos = std::min(startPos + chunkSize, static_cast<int>(data.size()));

    // Extract the chunk from the data vector
    std::vector<unsigned char> chunk(data.begin() + startPos, data.begin() + endPos);

    return chunk;
}

