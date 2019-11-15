#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>



int main() {

    int fd;
    char * fifo = "tmp/fifo";

    mkfifo(fifo, 0666);

    char fifo_output[80], fifo_input[80];

    while(1){
        fd = open(fifo, O_RDONLY);
        read(fd, fifo_output, 80);

        printf("from userspace: %s\n", fifo_output);
        close(fd);

        fd = open(fifo, O_WRONLY);
        fgets(fifo_input, 80, stdin);
        write(fd,fifo_input, strlen(fifo_input) + 1);
        close(fd);
    }
}