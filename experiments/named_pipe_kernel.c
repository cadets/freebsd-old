#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>



int main() {

    int fd;
    const char * fifo = "/tmp/fifo";
    printf("Welcome to kernel!\n");
    mkfifo(fifo, 0666);

    char fifo_output[80], fifo_input[80];

    while(1){
        fd = open(fifo, O_RDONLY);
        read(fd, fifo_output, 80);
        
        if(strlen(fifo_output) != 0)
        {
        printf("From userspace: %s\n", fifo_output);
        }
        close(fd);

        fd = open(fifo, O_WRONLY);
        fgets(fifo_input, 80, stdin);
        write(fd,fifo_input, strlen(fifo_input) + 1);
        close(fd);
    }
}