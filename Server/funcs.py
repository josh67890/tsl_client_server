import size, codes, crypty, struct, uuid

VERSION = 3

def encrypted_size(length):
    remainder = length%16
    return length+16-remainder



################################################  unpack functions  #################################################




def register_unpack(request, unpacked_request):
    decoded_name = request.decode('utf-8') # make sure the encoding is the same on the cliens side!!
    unpacked_request['name'] = decoded_name
    return # None - the dict is updated already

def key_request_unpack(request, unpacked_request):
    unpacked_request['name'] = request[:size.name].rstrip(b'\0').decode('utf-8')
    unpacked_request['public_key'] = request[size.name:].rstrip(b'\0') #verify that the fields are properly recieved? or rely on the fact that key exchange will fail if the names are wrong or the public key is invalid?
    return

def reconnect_unpack(request, unpacked_request):
    decoded_name = request.decode('utf-8')
    unpacked_request['name'] = decoded_name
    return 

def file_send_unpack(request, unpacked_request):
    offset1 = size.file_header+size.filename
    file_head = request[:size.file_header]
    file_name = request[size.file_header:offset1].rstrip(b'\0')
    file_contents = request[offset1:unpacked_request['payload_size']]
    unpacked_request['filename'] = file_name.decode('utf-8')
    unpacked_request['file_contents'] = file_contents #not decoded. decode upon full reception of message
    unpacked_request['content_size'], unpacked_request['org_size'], unpacked_request['packet_no'], unpacked_request['total_packs'] = struct.unpack('<IIHH', file_head)
    return


def crc_valid_unpack(request, unpacked_request):
    unpacked_request['filename'] = request.rstrip(b'\0').decode('utf-8')
    return

def crc_invalid_unpack(request, unpacked_request):
    unpacked_request['filename'] = request.rstrip(b'\0').decode('utf-8')
    return

def crc_fatal_unpack(request, unpacked_request):
    unpacked_request['filename'] = request.rstrip(b'\0').decode('utf-8')
    return

code_based_unpack = {codes.cl_reg:register_unpack, codes.public_key_to_srv:key_request_unpack, codes.client_reconn:reconnect_unpack, codes.file_from_client:file_send_unpack, codes.crc_valid:crc_valid_unpack, codes.crc_invalid:crc_invalid_unpack, codes.crc_fatal:crc_fatal_unpack}


def unpack_payload(request, code, unpacked_request):
    return code_based_unpack[code](request, unpacked_request) # will return /none, but update the unpacked_request dict


##################################### procces request functions #################################################

def register(request, clients):
    name = request['name']
    try:
        if name in clients: # entails name being the key of each client
            response = struct.pack('<H', codes.reg_fail)
            code = codes.reg_fail
        else:
            clients[name] = {'files':{}} # initialize client dict with file details dictionary (initially empty, of course - otherwise would not be registering for the first time)  
            cl_id = uuid.uuid4()
            clients[name]['uuid'] = cl_id.hex #saved in hex string form
            response = cl_id.bytes
            code = codes.reg_success
            clients[name]['connected'] = True # records if client is currently connected - unclear how to tell if client disconnected and needs to connect again
    except Exception:
        print("error occured while proccessing client\'s request")
        code = codes.err
        response = struct.pack('<H', code)
    return code, response


def recieve_key(request, clients, reconnect = False): # test if connected!!!
    try:
        name = request['name']
        if not reconnect:
            clients[name]['public_key'] = request['public_key']
            aes_key = crypty.get_aes_key()
            clients[name]['aes_key'] = aes_key #saved as bytes
        else:
            aes_key = clients[name]['aes_key']
        code = codes.symm_key_due_reg
        rsa_encrypted_key = crypty.rsa_encrypt(aes_key, clients[name]['public_key'])
        l = len(rsa_encrypted_key)
        response = bytes.fromhex(clients[name]['uuid'])+rsa_encrypted_key
    except Exception as e:
        print(f"error occured while proccessing client\'s request - {e}")
        code = codes.err
        response = struct.pack('<H', code)
    return code, response


def reconnect(request, clients):
    try:
        name = request['name']
        if name in clients and clients[name]['connected'] == False and clients[name]['aes_key']: # will fail if 1) not registered; 2)registered and already connected; 3) no aes key registered with client
            clients[name]['connected'] = True
            code, response = recieve_key(request, clients, reconnect=True) # incorrect code - reset in next line
            code = codes.symm_key_due_reconn
        else: # already connected or not yet registered
            code = codes.reconn_denied
            print('error while attempting to recconect client.\nperhaps client is not registered or already connected')
            response = bytes.fromhex(request['uuid'])
    except Exception:
        print("error occured while proccessing client\'s request")
        code = codes.err
        response = struct.pack('<H', code)   

    return code, response


def recieve_file(request, clients): # test if client is registered and has key!!
    

    try:
        request_id = request['uuid']
        name = get_name_for_uuid(request_id, clients)
        client = clients[name]
        pack_num = request['packet_no']
        total_packs = request['total_packs']
      
        client['pack_no'] = pack_num

        if pack_num == 0:
            client['filename'] = request['filename']
            client['file_contents'] = request['file_contents']
            client['total_packs'] =  total_packs # relies on the count remaining the same throughout the entire transmission - this **SHOULD** be the fact :)
        else:
            if client['filename']!=request['filename'] or client['next_pack']!=pack_num:
                raise Exception("invalid file info - not matching the current transmitted file.")
            client['file_contents'] += request['file_contents']
        client['next_pack'] = pack_num+1
        if pack_num == total_packs-1: # document fully transmitted - decrypt, calculate crc and send proper response
            # calculate checksum and send back to client
            aes_key = client['aes_key']
            decrypted_file_data = crypty.aes_decrypt(client['file_contents'], aes_key)
            client['file_contents'] = decrypted_file_data
            crc = calc_crc(client['file_contents'])
            bytes_id = bytes.fromhex(request['uuid'])
            bytes_contents_size = struct.pack('<I', request['content_size'])
            bytes_filename = request['filename'].encode('utf-8').ljust(size.filename, b'\0')
            bytes_crc = struct.pack('<I', crc)
            code = codes.file_crc_from_srv
            response = bytes_id+bytes_contents_size+bytes_filename+bytes_crc
        else:
            return None, None

    except Exception:
        print("error occured while proccessing client\'s request")
        code = codes.err
        response = struct.pack('<H', code)
    return code, response
        



def crc_valid(request, clients):
    try:
        client_id = request['uuid']
        name = get_name_for_uuid(client_id, clients)
        client = clients[name]
        filename = request['filename']
        if client['filename']!=filename:
                raise Exception("invalid filename's crc check")
        save_file(client)
        code = codes.msg_recieved
        response = bytes.fromhex(request['uuid'])
        client['failure_count'] = 0 # reset the failure count to zero
        client['connected'] = False #disconnects user - for reconnection purposes
    except Exception:
        print("error occured while proccessing client\'s request")
        code = codes.err
        response = struct.pack('<H', code)
    return code, response
    

def crc_invalid(request, clients):
    try:
        client_id = request['uuid']
        name = get_name_for_uuid(client_id, clients)
        client = clients[name]
        filename = request['filename']
        if client['filename']!=filename:
                raise Exception("invalid filename's crc check")
        
        # delete the bytes last recieved from client
        last_added = client['last_added_size']
        client['file_contents'] = bytes()
        client['failure_count'] += 1 # increment failure count
        code = codes.crc_invalid
        response = None
    except Exception:
        print("error occured while proccessing client\'s request")
        code = codes.err
        response = struct.pack('<H', code)
    return code, response # only in this case will no message be sent back to client - as per the protocol



def crc_fatal(request, clients):
    try:
        client_id = request['uuid']
        name = get_name_for_uuid(client_id, clients)
        client = clients[name]
        filename = request['filename']
        if client['filename']!=filename:
                raise Exception("invalid filename's crc check")
        code = codes.msg_recieved
        response = bytes.fromhex(request['uuid'])
    except Exception:
        print("error occured while proccessing client\'s request")
        code = codes.err
        response = struct.pack('<H', code)
    return code, response



proccess_dict = {codes.cl_reg:register, codes.public_key_to_srv:recieve_key, codes.client_reconn:reconnect, codes.file_from_client:recieve_file, codes.crc_valid:crc_valid, codes.crc_invalid:crc_invalid, codes.crc_fatal:crc_fatal}
# proccess request and return relevant packed response
def proccess_request(unpacked_request, code, clients):
    return proccess_dict[code](unpacked_request, clients)



def proccess_request_from_client(request, clients):
    header = request[:size.client_header]
    payload = request[size.client_header:].rstrip(b'\0')
    client_id, version, code, payload_size = deconstruct_header(header)
    unpacked_request = {'name':None, 'uuid':client_id, "payload_size":payload_size} #will always have a username - but will be None unless registered
    unpack_payload(payload, code, unpacked_request)
    response_code, response_payload = proccess_request(unpacked_request, code, clients)
    if response_code:
        response_payload_size = len(response_payload)
        response_header = construct_response_header(response_code, response_payload_size)
        return response_code, response_header+response_payload
    else:
        return None, None


def deconstruct_header(header):
    client_id = header[:size.id_size].hex() #translate to 64-character hex string
    header = header[size.id_size:]
    version, code, payload_size = struct.unpack('<BHI', header)
    return client_id, version, code, payload_size


def construct_response_header(code, payload_size):
    return struct.pack('<BHI', VERSION, code, payload_size)


def save_file(client): #IMPLEMENT!!!
    filename = client['filename']
    client['files'][filename] = get_file_details(client) #unsure what details should be here - implementing as just filename for now
    file_contents = client['file_contents']#saved as binary data
    with open(filename, "wb") as f: # if file exists, will be overwritten!!
        f.write(file_contents)
    


def get_file_details(client):
    return client['filename']

def calc_crc(decrypted_contents):#IMPLEMENT!!!
    checksum = sum(decrypted_contents) & int("ff"*4, base=16)
    return checksum


def get_name_for_uuid(request_id, clients):
    for name in clients:
        if clients[name]['uuid'] == request_id:
            return name
    return None