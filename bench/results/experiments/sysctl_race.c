#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static char buf[4];
static atomic_int writing;
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
		while (!atomic_load(&writing) && !atomic_load(&done))
			;
		struct timespec t0, t;
		clock_gettime(CLOCK_MONOTONIC, &t0);
		long wait = rand_r(&seed) % 2000;
		do
			clock_gettime(CLOCK_MONOTONIC, &t);
		while ((t.tv_sec - t0.tv_sec) * 1000000000L + t.tv_nsec - t0.tv_nsec < wait);
		memcpy(buf, "99", 2);
		while (atomic_load(&writing) && !atomic_load(&done))
			;
	}
	return NULL;
}

int main(int argc, char **argv)
{
	int n = atoi(argv[1]), applied99 = 0;
	int fd = open("/proc/sys/net/ipv4/ip_default_ttl", O_RDWR);
	pthread_t th;
	char back[8];

	pin(2);
	pthread_create(&th, NULL, flipper, NULL);
	for (int i = 0; i < n; i++) {
		memcpy(buf, "64\n", 3);
		atomic_store(&writing, 1);
		pwrite(fd, buf, 3, 0);
		atomic_store(&writing, 0);
		pread(fd, back, sizeof(back), 0);
		applied99 += back[0] == '9';
		usleep(100);
	}
	atomic_store(&done, 1);
	pthread_join(th, NULL);
	printf("applied: 99=%d 64=%d\n", applied99, n - applied99);
	return 0;
}
