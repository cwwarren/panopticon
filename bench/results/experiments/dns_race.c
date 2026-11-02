#define _GNU_SOURCE
#include <arpa/inet.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static char buf[64];
static atomic_int sending;
static atomic_int done;

static void pin(int cpu)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
}

static void *flipper(void *arg)
{
	unsigned seed = 1;
	pin(3);
	while (!atomic_load(&done)) {
		while (!atomic_load(&sending) && !atomic_load(&done))
			;
		struct timespec t0, t;
		clock_gettime(CLOCK_MONOTONIC, &t0);
		long wait = rand_r(&seed) % 3000;
		do
			clock_gettime(CLOCK_MONOTONIC, &t);
		while ((t.tv_sec - t0.tv_sec) * 1000000000L + t.tv_nsec - t0.tv_nsec < wait);
		memcpy(buf + 13, "evil", 4);
		while (atomic_load(&sending) && !atomic_load(&done))
			;
	}
	return NULL;
}

int main(int argc, char **argv)
{
	int n = atoi(argv[1]);
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in dst = {.sin_family = AF_INET, .sin_port = htons(53)};
	pthread_t th;

	inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);
	pin(2);
	pthread_create(&th, NULL, flipper, NULL);
	for (int i = 0; i < n; i++) {
		memset(buf, 0, sizeof(buf));
		buf[2] = 1;
		buf[5] = 1;
		buf[12] = 4;
		memcpy(buf + 13, "good", 4);
		buf[17] = 3;
		memcpy(buf + 18, "com", 3);
		buf[23] = 1;
		buf[25] = 1;
		atomic_store(&sending, 1);
		sendto(fd, buf, 26, 0, (struct sockaddr *)&dst, sizeof(dst));
		atomic_store(&sending, 0);
		usleep(50);
	}
	atomic_store(&done, 1);
	pthread_join(th, NULL);
	return 0;
}
