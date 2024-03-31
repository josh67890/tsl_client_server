

namespace codes{
	//client codes
	extern int cl_reg;
	extern int public_key_to_srv;
	extern int client_reconn;
	extern int file_from_client;
	extern int crc_valid;
	extern int crc_invalid;
	extern int crc_fatal;


	//server codes
	extern int reg_success;
	extern int reg_fail;
	extern int symm_key_due_reg;
	extern int file_crc_from_srv;
	extern int msg_recieved;
	extern int symm_key_due_reconn;
	extern int reconn_denied;

	extern int err;
}