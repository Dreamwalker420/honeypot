/* Kirk Powell
 * CS 410/591 - Final Project (Client)
 * May 2, 2016
 * 
 * Sources:
 	CS407 Lab Solutions by Kirk Powell
	"The Linux Programming Interface" [2010] by Michael Kerrisk
 	"Beginning Linux Programming" [2008] by Matthew and Stone.
 *
 */

// These are implemented by tpool.c
 
typedef struct queue_object queue_object_t;
typedef struct tpool_object tpool_object_t;

int destroy_thread_pool_resources();
int tpool_add_task(int newtask);
int tpool_init(void (*process_task)(int));