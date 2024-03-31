
import threading, socket,  struct, size, codes, crypty, funcs

port_details_file = 'port.info'
 
def initialize_server():
    port = get_port_number() # defaults to localhost
    host = get_host()
    clients_details = get_details_for_all_clients() # will anyhow return an empty dictionary if not implemented, so we can use it freely
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()

    print(f"server listening on {host}:{port}")

    while True: #waits for client connection requests
        client_socket, client_address = server_socket.accept()
        print(f"connection recived from {client_address}")

        threading.Thread(target = client_handler, args = (client_socket, clients_details)).start() # dispatches each client connection to seperate handler thread


def client_handler(client_socket, clients):  #continues to proccess requests from client until client disconnects

    while True:
        request_from_client = client_socket.recv(size.pack)

        if not request_from_client: #client disconnected - VERIFY THIS DOES WHAT IS EXPECTED!!!
            break
            
        msg_code, response = funcs.proccess_request_from_client(request_from_client, clients)
        if not msg_code or msg_code == codes.crc_invalid: # no message sent back to client specifically in these cases
            continue 
        if msg_code == codes.err:
            print("unhandled error occured on server side.")
        padded_response = response.ljust(size.pack, b'\0')
        print(f"sending response of code {msg_code} - length of message: {len(response)}")
        sent = client_socket.send(padded_response)
        print(f"sent response of code {msg_code} - length of message sent: {sent}")
        if msg_code == codes.msg_recieved: #disconnect
            print("client connection disconnecting...")
            break
    client_socket.close()



def get_host():
    return '127.0.0.1' # defaults to localhost - can obviously be changed to something else


def get_port_number():
    try:
        port_file = open(port_details_file, 'r')
        port = int(port_file.readline())
        port_file.close()
    except Exception:
        port = 1256
        print(f"WARNING: no data available for server port number.\nopened on default port no. {port}")
    return port

#  if implemented Q3 - otherwise will return an empty clients dict - as is needed in this program anyhow
def get_details_for_all_clients():
    details = {}
    # try:
    #     with open(clients_data_file, 'r') as clients_file:
    #         for line in clients_file:
    #             client = [l.strip() for l in line.split(':')]
    #             details[client[0]] = {'name':client[1], 'psw':client[2], 'last_seen':client[3]} # each client is mapped to uuid key
    #             for k in details[client[0]].values():
    #                 if not k:
    #                     print('AAA')
    #                     raise Exception(f'unable to parse {clients_data_file} file')
    #             if len(client) != 4:
    #                 print('BBB')
    #                 raise Exception(f'unable to parse {clients_data_file} file')
    # except Exception:
    #     print(f"error occured while parsing client file")
    return details

if __name__ == "__main__":
    initialize_server()