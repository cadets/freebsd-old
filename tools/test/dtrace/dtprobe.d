#pragma option quiet

sdt:::probe
/args[5]/
{
	printf("6 args %s %s %s %s %s %s\n", copyinstr(args[0]),
	    copyinstr(args[1]), copyinstr(args[2]), copyinstr(args[3]),
	    copyinstr(args[4]), copyinstr(args[5]));
}

sdt:::probe
/args[5] == NULL/
{
	printf("5 args %s %s %s %s %s\n", copyinstr(args[0]),
	    copyinstr(args[1]), copyinstr(args[2]), copyinstr(args[3]),
	    copyinstr(args[4]));
}

sdt:::probe
/args[4] == NULL/
{
	printf("4 args %s %s %s %s\n", copyinstr(args[0]),
	    copyinstr(args[1]), copyinstr(args[2]), copyinstr(args[3]));
}

sdt:::probe
/args[3] == NULL/
{
	printf("3 args %s %s %s\n", copyinstr(args[0]), copyinstr(args[1]),
	    copyinstr(args[2]));
}

sdt:::probe
/args[2] == NULL/
{
	printf("2 args %s %s\n", copyinstr(args[0]),
	    copyinstr(args[1]));
}

sdt:::probe
/args[1] == NULL/
{
	printf("1 arg %s\n", copyinstr(args[0]));
}
