
#pragma once
#include <string>
#include <vector>

namespace structs{

    struct keys {
        std::vector<unsigned char> public_key;
        std::vector<unsigned char> private_key;
    };

    struct file_info {
        std::string filename;
        std::vector<unsigned char> encrypted_data;
        int original_size;
        int encrypted_size;
        int pack_no;
        int total_packs;
    };

    struct client_info {
        std::string host;
        std::string port;
        std::string name;
        std::vector<unsigned char> uuid;
        std::vector<unsigned char> private_key;
        struct file_info *file_info;
        struct keys* keys;
    };

    struct response_info {
        int version;
        int code;
        int payload_size;
    };

    struct response_data {
        int code;
        std::string id;
        std::vector<unsigned char> encrypted_aes_key;
        int content_size;
        std::string filename;
        int crc;
    };

    

    

}


/*struct transfer_info {
     std::string host;
     std::string port;
     std::string name;
     std::string filename;
 };

 struct me_info {
     std::string name;
     std::vector<unsigned char> uuid;
     std::vector<unsigned char> private_key;
 };*/

       
