

namespace size {
	int pack = 1024;
	int id_size = 16;

	int name_block = 255;
	int name_max = 100;
	int password = 255;

	int version = 1;
	int code_no = 2;
	int payload = 4;

	int iv = 16;
	int aes_key = 32;
	int rsa_public_key = 160;
	int rsa_real_size = 1024;

	int contents = 4;
	int org_file = 4;
	int pack_no = 2;
	int pack_count_total = 2;
	int filename = 255;
	int crc = 4;

	int server_header = version + code_no + payload;
	int client_header = version + code_no + payload + id_size;
	int file_header = contents + org_file + pack_no + pack_count_total + filename; 
	int file_payload = pack - client_header - file_header;
}