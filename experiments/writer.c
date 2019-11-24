#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

static void *write_script(void *file_path)
{
    char *path = (char *)file_path;
    FILE *fp;
    char *d_script;

    if ((fp = fopen(path, "r")) == NULL)
    {
        printf("Write thread: Failed to open file '%s. \n", path);
        exit(1);
    }

    int file_size = 0;

    fseek(fp, 0L, SEEK_END);
    file_size = ftell(fp);

    printf("Write thread: Size of file is: %d. \n", file_size);

    rewind(fp);

    d_script = malloc(sizeof(char) * file_size);

    if ((fgets(d_script, file_size, fp)) == NULL)
    {
        printf("Write thread: Error occured while reading script. \n");
        exit(3);
    }

    fclose(fp);

    int fd;

    const char *fifo = "/tmp/fifo";

    mkfifo(fifo, 0666);

    fd = open(fifo, O_WRONLY);

    int l = write(fd, d_script, file_size + 1);

    printf("Write thread: I've written in pipe %d. \n", l);

    close(fd);
    free(d_script);

    // delete fifo
    unlink(fifo);
    
    pthread_exit(NULL);
}

int main(int argc, char **argv)
{
    char *file_path = argv[1];

    pthread_t write_thread;

    pthread_create(&write_thread, NULL, write_script, file_path);

    pthread_join(write_thread, NULL);

    return 0;
}
