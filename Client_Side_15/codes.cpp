
namespace codes {

	//client codes
	int cl_reg = 1025;
	int public_key_to_srv = 1026;
	int client_reconn = 1027;
	int file_from_client = 1028;
	int crc_valid = 1029;
	int crc_invalid = 1030;
	int crc_fatal = 1031;


	//server codes
	int reg_success = 1600;
	int reg_fail = 1601;
	int symm_key_due_reg = 1602;
	int file_crc_from_srv = 1603;
	int msg_recieved = 1604;
	int symm_key_due_reconn = 1605;
	int reconn_denied = 1606;

	int err = 1607;

}