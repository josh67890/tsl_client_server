import crypty, funcs, size

def write_binary_data_to_file(file_path, binary_data):
    with open(file_path, 'wb') as file:
        file.write(binary_data)

def read_binary_data(filename):
    try:
        with open(filename, "rb") as file:
            binary_data = file.read()
            return binary_data
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
        return None
    except Exception as e:
        print(f"Error occurred while reading '{filename}': {e}")
        return None

def main():
    import struct
    filename = "C:/Users/Dell/source/repos/test_15/test.txt"
    request = read_binary_data(filename)
    for i in range(len(request)):
        print(struct.unpack('B', request[i:i+1])[0], end=" ")
    print("\n\ndeconstructed:")
    client_dict = {}
    code, response = funcs.proccess_request_from_client(request, client_dict)
    print(code, response)
    print(response[-(size.id_size):].hex())
    write_binary_data_to_file(filename, response)







if __name__ == "__main__":
    main()
 


# import struct, os, time
    # filename = "C:/Users/Dell/source/repos/test_15/key.data"
    # binary_data = read_binary_data(filename)
    # if binary_data:
    #     print("key data read successfully:")
    #     print(f"key length: {len(binary_data)}")
    #     for i in range(len(binary_data)):
    #         print(struct.unpack('B', binary_data[i:i+1])[0], end=" ")
    # aes = crypty.get_aes_key()
    # encrypted_aes_key = crypty.rsa_encrypt(aes, binary_data)
    # for i in range(len(encrypted_aes_key)):
    #         print(struct.unpack('B', encrypted_aes_key[i:i+1])[0], end=" ")
    # print()
    # write_binary_data_to_file("C:/Users/Dell/source/repos/test_15/key.data", encrypted_aes_key)
    # print("encrypted aes key transmitted successfully")
    # time.sleep(10)

    # binary_data = read_binary_data(filename)
    # decrypted_data = crypty.aes_decrypt(binary_data, aes)
    # print(f"data from client decrypted successfully\nmessage is: {decrypted_data.decode()}")    
    
    # priavte_key, public_key = crypty.generate_rsa_keys(1024)
    # data = "hello there, amazing beautiful Yael! \nI love you!".encode('utf-8')
    # rsa_encrypted = crypty.rsa_encrypt(data,public_key)
    # for i in range(len(rsa_encrypted)):
    #     print(struct.unpack('B', rsa_encrypted[i:i+1])[0], end=" ")
    # print(f"\nsize of encrypted message:  {len(rsa_encrypted)}")

    # rsa_decrypted = crypty.rsa_decrypt(rsa_encrypted, priavte_key)
    # print(f"decrypted message: {rsa_decrypted.decode('utf-8')}")
    