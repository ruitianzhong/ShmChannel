#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <size-in-bytes>\n", argv[0]);
        return 1;
    }
    size_t size = strtoul(argv[1], NULL, 10);
    char *p = malloc(size);
    if (!p) {
        perror("malloc");
        return 1;
    }
    for (size_t i = 0; i < size; i++)
        p[i] = (char)rand();
    free(p);
    return 0;
}