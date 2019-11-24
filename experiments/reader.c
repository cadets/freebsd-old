#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

static void *read_script()
{
    printf("here");

    int fd;
    const char *fifo = "/tmp/fifo";

    static char *d_script;

    if ((fd = open(fifo, O_RDONLY)) == -1)
    {
        printf("Read thread: Failed to open named pipe %s. \n", fifo);
    }

    d_script = malloc(sizeof(char) * 80);

    int l;
    if ((l = read(fd, d_script, 80)) == -1)
    {
        printf("Read thread: Error occured while reading from the pipe. \n");
        exit(2);
    }

    printf("Read thread: Read from fifo %d. \n", l);

    printf("Read thread: Script is %s. \n", d_script);
    close(fd);
    free(d_script);

    pthread_exit(NULL);
}

int main(int argc, char **argv)
{
    pthread_t read_thread;

    pthread_create(&read_thread, NULL, read_script, NULL);

    pthread_join(read_thread, NULL);

    return 0;
}
