
/*
 *	sh*:::cmd		crt call setting up the process to run
 *		arg0: char* pointer to shell command 
 */
provider sh {
	probe sh__cmd( char* cmd );
};
