import funcs
pack = 1024
id_size = 16

name = 255
password = 255

version = 1
code_no = 2
payload = 4

iv = 16
aes_key = 32
rsa_public_key = 160
rsa_real_key = 128

crc = 4
contents = 4
org_file = 4
pack_no_total = 4 
filename = 255

server_header = version+code_no+payload
client_header = version+code_no+payload+id_size
file_header = contents+org_file+pack_no_total

# name = password = 254
# enc_ver = funcs.encrypted_size(version)
# key_payload = iv+enc_nonce+enc_aes
# ticket = version+id_size*2+time+iv+enc_aes+enc_time
# authenticator = iv+enc_ver+enc_id*2+enc_time
# message = 4
# time = 8
# enc_time = funcs.encrypted_size(time)
# nonce = 8
# enc_nonce = funcs.encrypted_size(nonce)
# enc_id = funcs.encrypted_size(id_size)
# ip = 4
# port = 2