#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static void *burn_cpu(void *arg)
{
    (void)arg;
    /* 死循环，占满一个逻辑核 */
    volatile unsigned long x = 0;
    for (;;) {
        x++;
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <n>\n", argv[0]);
        return 1;
    }

    int n = atoi(argv[1]);
    if (n <= 0) {
        fprintf(stderr, "n must be > 0\n");
        return 1;
    }

    pthread_t *threads = malloc(sizeof(pthread_t) * n);
    if (!threads) {
        perror("malloc");
        return 1;
    }

    for (int i = 0; i < n; i++) {
        if (pthread_create(&threads[i], NULL, burn_cpu, NULL) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    for (int i = 0; i < n; i++)
        pthread_join(threads[i], NULL);

    free(threads);
    return 0;
}