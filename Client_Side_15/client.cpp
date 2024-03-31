#include <iostream>
#include <boost/asio.hpp>
#include "size.h"
#include "codes.h"
#include "client_utils.h"
#include "request_utils.h"
#include "structs.h"
#include "crypty.h"
#include "file_utils.h"
#include <thread>
#include <chrono>

using boost::asio::ip::tcp;

int main() {
    try {

        ///////////////////////////       initialization          /////////////////////////
        structs::client_info info;
        structs::file_info file;
        info.file_info = &file;
        structs::keys keys;
        
        // get personal data from transfer.info - host-port of server, \n name of client \n document path(relative!) V
        client_utils::get_data_from_transfer_info("transfer.info", info);
        // get personal data from me.info - name of client, \n  32-character uuid (32 byte)   \n   aes symmetric key - base64 encoded!! V
        client_utils::get_data_from_me_info("me.info", info);   // client name is overwritten by me.info, if file is present


        bool registered = !info.private_key.empty(); // will send registration request based on this

        // connect to server
        boost::asio::io_context io_context;
        tcp::resolver resolver(io_context);
        tcp::resolver::results_type endpoints = resolver.resolve(info.host, info.port);
        tcp::socket socket(io_context);
        boost::asio::connect(socket, endpoints);

        
        std::vector<unsigned char> response_from_server(size::pack);

        if (!registered) {  // if not registered, 

            //send register request
            std::vector<unsigned char> request = requests::construct_request(info, codes::cl_reg);
            boost::asio::write(socket, boost::asio::buffer(request));

            // recieve response with uuid

            boost::asio::read(socket, boost::asio::buffer(response_from_server));

            structs::response_data response = requests::unpack_server_response(response_from_server);

            // create me.info and write to it: client name  \n  **hex uuid**   \n  private rsa key
            info.uuid = client_utils::hexStringToBytes(response.id);

            // create and write to priv.key the rsa pair
            keys = crypty::generate_rsa_pair();
            info.keys = &keys;
            client_utils::save_rsa_pair_to_priv_key("priv.key", keys);
            client_utils::save_client_data_to_me_info("me.info", info, response, keys);

            // send key request to server
            std::vector<unsigned char> key_request = requests::construct_request(info, codes::public_key_to_srv);
            boost::asio::write(socket, boost::asio::buffer(key_request));
        }


        else {  // if registered already - 
            //  read the public key from priv.key - if registered already
            keys = client_utils::read_keys_from_priv_key("priv.key");
            info.keys = &keys;
            // need error handling for case in which invalid key values are stored in priv.key
           
            //  send reconnect request
            std::vector<unsigned char> request = requests::construct_request(info, codes::client_reconn);
            boost::asio::write(socket, boost::asio::buffer(request));

            
        }



        

        // all continue here:
        // recieve rsa-encrypted aes-key from server
        
        while (!boost::asio::read(socket, boost::asio::buffer(response_from_server)));
        structs::response_data response = requests::unpack_server_response(response_from_server);



        // decrypt aes key -
        // 
        // 
        //  ****************** SHOULD BE THE FORMAT FOR AES-CBC ENCRYPTION IN CRYPTO++ *************


        std::vector<unsigned char> aes_key = crypty::rsa_decrypt(keys, response.encrypted_aes_key);


        //////////////////////////    FILE TRANSMISSION  //////////////////////////////////// 


        // read the entire file as binary
        std::vector<unsigned char> file_binary = file_utils::read_data_to_transmit_from_file(info.file_info->filename);

        //compute crc
        int crc = file_utils::calculate_crc(file_binary);

        // record size of original file - casts explicitly to int from size_t - according to protocol that size field is 4 bytes/int - may cause overflow for large files
        int original_file_size = (int)file_binary.size();

        // encrypt file AS A WHOLE
        std::vector<unsigned char> encrypted_file = crypty::aes_encrypt(aes_key, file_binary);

        // record size of encrypted file
        int encrypted_file_size = (int)encrypted_file.size();
        int pack_count = file_utils::calculate_pack_count(encrypted_file_size);

        info.file_info->original_size = original_file_size;
        info.file_info->total_packs = pack_count;

        // in a for loop of 3 times:
        int i;
        for (i = 0; i < 3; i++) {
            // in a loop - 
            for (int j = 0; j < pack_count; j++) {

                //create packets of ecrypted file chuncks and send them over the network.
                info.file_info->encrypted_data = file_utils::get_next_chunk(encrypted_file, j);
                info.file_info->encrypted_size = encrypted_file_size;
                info.file_info->pack_no = j;

                std::vector<unsigned char> file_request = requests::construct_request(info, codes::file_from_client);
                boost::asio::write(socket, boost::asio::buffer(file_request));
            }
            // when finished, recieve from server crc
            while (!boost::asio::read(socket, boost::asio::buffer(response_from_server)));
            structs::response_data response = requests::unpack_server_response(response_from_server);

            // test crc against original crc - if valid, send crc_valid and break
            if (response.crc == crc) {
                std::vector<unsigned char> crc_request = requests::construct_request(info, codes::crc_valid);
                boost::asio::write(socket, boost::asio::buffer(crc_request));
                break;
            }
            // if invalid, send crc_invalid (only for turn 1,2!!)
            else {
                if (i < 2) { // if failed three times it will send crc_fatal
                    std::vector<unsigned char> crc_request = requests::construct_request(info, codes::crc_invalid);
                    boost::asio::write(socket, boost::asio::buffer(crc_request));
                }
            }

        }
        // if erred 3 times in transmitting the file, abort with crc_fatal
        if (i == 3) {
            std::vector<unsigned char> crc_request = requests::construct_request(info, codes::crc_fatal);
            boost::asio::write(socket, boost::asio::buffer(crc_request));
        }
        // recieve final message from server - in any case must happen
        while (!boost::asio::read(socket, boost::asio::buffer(response_from_server)));
        /*structs::response_data */response = requests::unpack_server_response(response_from_server);
        if (response.code != codes::msg_recieved) {
            socket.close();
            throw std::runtime_error("server responded with error");
        }
        else {
            std::cout << "server has finished protocol with success code " << response.code << std::endl;
            socket.close();
        }
    }
    catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        

    }

    return 0;
}
