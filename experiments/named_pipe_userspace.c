#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

int main() {

    int fd;

    const char* fifo = "/tmp/fifo";
    printf("Welcome to userspace!\n");

    mkfifo(fifo, 0666);

    char fifo_input[80], fifo_output[80];

    while(1) {
        
        // everything is a file
       fd = open(fifo, O_WRONLY);

       fgets(fifo_input,80,stdin);
       write(fd, fifo_input, strlen(fifo_input)+1);
       close(fd);

       fd = open(fifo, O_RDONLY);

       read(fd,fifo_output,sizeof(fifo_output));
   
        if(strlen(fifo_output) != 0)
        {
       printf("from kernel: %s\n", fifo_output);
        }
       close(fd);

    }

    return 0;
}