/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Tiny producer-consumer program used to demonstrate the fuzzing scheduler.
 *
 * The producer appends a timestamped item every 20ms. The consumer removes one
 * item every 10ms and aborts the program if the item it pulled is older than
 * one second. Under a normal scheduler the consumer keeps up and items never
 * get that old, so the program runs forever. Under the fuzzing scheduler the
 * consumer thread can be starved long enough that a buried item goes stale,
 * which trips the check and crashes the program.
 *
 * The sample target carried from the concurrency-fuzz-scheduler PoC. Under
 * bedrock its clock (clock_gettime(CLOCK_MONOTONIC)) and srand() seed both
 * derive from the deterministic emulated TSC, so the crash reproduces from a
 * fixed scheduler seed.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define ITEM_LIFETIME_MS 1000

struct item {
	long long timestamp_ms;
	int value;
	struct item *next;
};

/* A mutex protected stack: push and pop both touch the head, so old items can
 * sit near the bottom for a long time, exactly like a ConcurrentLinkedDeque
 * used as a stack. */
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct item *head;

static long long now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void sleep_ms(long millis)
{
	struct timespec ts = {
		.tv_sec = millis / 1000,
		.tv_nsec = (millis % 1000) * 1000000,
	};
	nanosleep(&ts, NULL);
}

static void produce(int value)
{
	struct item *it = malloc(sizeof(*it));
	if (!it) {
		perror("malloc");
		exit(2);
	}
	it->timestamp_ms = now_ms();
	it->value = value;

	pthread_mutex_lock(&lock);
	it->next = head;
	head = it;
	pthread_mutex_unlock(&lock);
}

static int consume(void)
{
	pthread_mutex_lock(&lock);
	struct item *it = head;
	if (it)
		head = it->next;
	pthread_mutex_unlock(&lock);

	if (!it)
		return -1;

	long long age = now_ms() - it->timestamp_ms;
	int value = it->value;
	if (age >= ITEM_LIFETIME_MS) {
		fprintf(stderr, "Item is invalid! age %lldms\n", age);
		free(it);
		exit(1);
	}
	free(it);
	return value;
}

static void *producer_main(void *arg)
{
	(void)arg;
	for (;;) {
		produce(rand() % 100);
		sleep_ms(20);
	}
	return NULL;
}

static void *consumer_main(void *arg)
{
	(void)arg;
	for (;;) {
		consume();
		sleep_ms(10);
	}
	return NULL;
}

int main(void)
{
	pthread_t producer, consumer;

	srand((unsigned int)now_ms());
	pthread_create(&producer, NULL, producer_main, NULL);
	pthread_create(&consumer, NULL, consumer_main, NULL);

	pthread_join(producer, NULL);
	pthread_join(consumer, NULL);
	return 0;
}
