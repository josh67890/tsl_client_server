#pragma once
#include "structs.h"


class crypty {
private:


public:
	static structs::keys generate_rsa_pair();
	static std::vector<unsigned char> rsa_decrypt(const structs::keys& keys, std::vector<unsigned char> encrypted);
	static std::vector<unsigned char> rsa_encrypt(const structs::keys& keys, std::vector<unsigned char> plaintext);
	static std::vector<unsigned char> aes_encrypt(const std::vector<unsigned char>& aes_key, std::vector<unsigned char>& file_data);
	static std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char>& aes_key, std::vector<unsigned char>& encrypted_data);
};