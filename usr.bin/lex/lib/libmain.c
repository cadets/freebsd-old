/* libmain - flex run-time support library "main" function */

/* $Header$
 * $FreeBSD: head/usr.bin/lex/lib/libmain.c 52555 1999-10-27 07:56:49Z obrien $ */

extern int yylex();

int main( argc, argv )
int argc;
char *argv[];
	{
	while ( yylex() != 0 )
		;

	return 0;
	}
