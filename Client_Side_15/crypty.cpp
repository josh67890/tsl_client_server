#include "crypty.h"
#include <string>
#include "structs.h"
#include "size.h"

#include <osrng.h>
#include <rsa.h>
#include <aes.h>
#include <modes.h>
#include <filters.h>
#include <iostream>
#include <base64.h>
#include <files.h>
#include <pwdbased.h>



/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
structs::keys crypty::generate_rsa_pair() {
    CryptoPP::AutoSeededRandomPool rng;

    // Generate RSA key pair
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, size::rsa_real_size); // You can adjust the key size as per your requirements

    // Create public and private keys
    CryptoPP::RSA::PrivateKey privateKey(params);
    CryptoPP::RSA::PublicKey publicKey(params);

    // Convert private key to byte vector
    CryptoPP::ByteQueue privateKeyByteQueue;
    privateKey.Save(privateKeyByteQueue);
    std::vector<unsigned char> privateKeyVector(privateKeyByteQueue.MaxRetrievable());
    privateKeyByteQueue.Get(privateKeyVector.data(), privateKeyVector.size());

    // Convert public key to byte vector
    CryptoPP::ByteQueue publicKeyByteQueue;
    publicKey.Save(publicKeyByteQueue);
    std::vector<unsigned char> publicKeyVector(publicKeyByteQueue.MaxRetrievable());
    publicKeyByteQueue.Get(publicKeyVector.data(), publicKeyVector.size());

    // Store byte vectors in structs::keys
    structs::keys keyPair;
    keyPair.public_key = publicKeyVector;
    keyPair.private_key = privateKeyVector;

    return keyPair;
}

std::vector<unsigned char> crypty::rsa_decrypt(const structs::keys& keys, std::vector<unsigned char> encrypted) {
    CryptoPP::AutoSeededRandomPool rng;

    // Load RSA private key from byte vector
    CryptoPP::ByteQueue privateKeyByteQueue;
    privateKeyByteQueue.Put(keys.private_key.data(), keys.private_key.size());
    CryptoPP::RSA::PrivateKey privateKey;
    privateKey.Load(privateKeyByteQueue);

    // Decrypt using RSA
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    std::string decrypted;
    CryptoPP::StringSource(encrypted.data(), encrypted.size(), true, new CryptoPP::PK_DecryptorFilter(rng, decryptor, new CryptoPP::StringSink(decrypted)));

    // Convert decrypted string to byte vector
    std::vector<unsigned char> decryptedVector(decrypted.begin(), decrypted.end());

    return decryptedVector;
}

std::vector<unsigned char> crypty::rsa_encrypt(const structs::keys& keys, std::vector<unsigned char> plaintext) {
    std::vector<unsigned char> encrypted;

    try {
        // Load RSA public key
        CryptoPP::RSA::PublicKey rsa_public_key;
        CryptoPP::ByteQueue publicKey;
        publicKey.Put(keys.public_key.data(), keys.public_key.size());
        publicKey.MessageEnd();
        rsa_public_key.Load(publicKey);

        // Create RSA encryptor object
        CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(rsa_public_key);

        // Create AutoSeededRandomPool for random number generation
        CryptoPP::AutoSeededRandomPool rng;

        // Encrypt using RSA
        CryptoPP::ArraySource(plaintext.data(), plaintext.size(), true,
            new CryptoPP::PK_EncryptorFilter(rng, encryptor,
                new CryptoPP::VectorSink(encrypted)));

        if (encrypted.empty()) {
            std::cerr << "Encryption failed: Encrypted data is empty" << std::endl;
        }
    }
    catch (const CryptoPP::Exception& ex) {
        // Handle encryption error
        std::cerr << "Encryption error: " << ex.what() << std::endl;
    }

    return encrypted;
}

std::vector<unsigned char> crypty::aes_encrypt(const std::vector<unsigned char>& aes_key, std::vector<unsigned char>& file_data) {
    // Encrypt using AES-CBC
    std::vector<unsigned char> encrypted;

    try {
        // Use an IV of 16 zero bytes
        std::vector<unsigned char> iv(CryptoPP::AES::BLOCKSIZE, 0);

        // AES encryption
        CryptoPP::AES::Encryption aesEncryption(aes_key.data(), aes_key.size());
        CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv.data());

        // Perform encryption
        CryptoPP::StringSource(file_data.data(), file_data.size(), true,
            new CryptoPP::StreamTransformationFilter(cbcEncryption,
                new CryptoPP::VectorSink(encrypted)
            )
        );
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "AES encryption error: " << e.what() << std::endl;
        return std::vector<unsigned char>();
    }

    return encrypted;
}

std::vector<unsigned char> crypty::aes_decrypt(const std::vector<unsigned char>& aes_key, std::vector<unsigned char>& encrypted_data) {
    std::vector<unsigned char> decrypted;

    try {
        // Initialize IV to 16 zero bytes
        std::vector<unsigned char> iv(CryptoPP::AES::BLOCKSIZE, 0);

        // AES decryption
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption aesDecryption;
        aesDecryption.SetKeyWithIV(aes_key.data(), aes_key.size(), iv.data(), CryptoPP::AES::BLOCKSIZE);

        // Decrypt using AES CBC mode
        CryptoPP::StreamTransformationFilter decryptor(aesDecryption, new CryptoPP::VectorSink(decrypted));
        decryptor.Put(encrypted_data.data(), encrypted_data.size());
        decryptor.MessageEnd();

        // Crypto++ automatically handles PKCS #7 padding removal
    }
    catch (const CryptoPP::Exception& ex) {
        // Handle decryption error
        std::cerr << "Decryption error: " << ex.what() << std::endl;
        return std::vector<unsigned char>(); // Return an empty vector on error
    }

    return decrypted;
}

