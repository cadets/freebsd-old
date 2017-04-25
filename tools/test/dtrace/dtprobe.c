#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/dtrace.h>

int main(int argc, char **argv)
{
	int args[5];

	for (int i = 0;i <= 5; i++)
		args[i] = i;

	switch (argc) {
	case 1:
		dt_probe((uintptr_t)args[0], (uintptr_t)args[1],
			 (uintptr_t)args[2], (uintptr_t)args[3],
			 (uintptr_t)args[4], (uintptr_t)args[5]);
		break;
	case 2:
		dt_probe((uintptr_t)argv[1], 0, 0, 0, 0, 0);
		break;
	case 3:
		dt_probe((uintptr_t)argv[1], (uintptr_t)argv[2],
			 0, 0, 0, 0);
		break;
	case 4:
		dt_probe((uintptr_t)argv[1], (uintptr_t)argv[2], 
			 (uintptr_t)argv[3], 0, 0, 0);
		break;
	case 5:
		dt_probe((uintptr_t)argv[1], (uintptr_t)argv[2],
			 (uintptr_t)argv[3], (uintptr_t)argv[4],
			 0, 0);
		break;
	case 6:
		dt_probe((uintptr_t)argv[1], (uintptr_t)argv[2],
			 (uintptr_t)argv[3], (uintptr_t)argv[4],
			 (uintptr_t)argv[5], 0);
		break;
	case 7:
		dt_probe((uintptr_t)argv[1], (uintptr_t)argv[2], 
			 (uintptr_t)argv[3], (uintptr_t)argv[4],
			 (uintptr_t)argv[5], (uintptr_t)argv[6]);
		break;
	default:
		printf("dtprobe takes between 1 and 5 arguments.");
	}
}
