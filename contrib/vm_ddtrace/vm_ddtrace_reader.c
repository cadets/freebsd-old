/*
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
 #include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int
main(int argc, char **argv)
{
    int vtdtr;

    vtdtr = open("/dev/vtdtr", O_RDONLY);
}