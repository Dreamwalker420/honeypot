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

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include "tpool.h"
#include <unistd.h>

/* --------------------------------------------------------------------------------------*/
// Structures for tpool.c

// Create global variable struct type for job queue for workers to access
typedef struct queue_object{
	// Pointer to the buffer
	int *queue_buffer;
	// Size of the buffer
	size_t buffer_length;
	// Keep track of how many jobs in the queue
	int jobs_available;
	// Keep track of linked list of jobs
	size_t current_job;
	size_t latest_job;
	// Keep track of a mutex for read/write privilege on the queue
	pthread_mutex_t rwlock;
	// Keep track of a mutex to prevent busy-waiting
	pthread_mutex_t process_lock;
	pthread_cond_t job_count;
} queue_object_t;

// Create global variable struct type for thread pool object
typedef struct tpool_object{
	// Function for referencing in worker threads
	void (*call_this_function)(int);
} tpool_object_t;


/* --------------------------------------------------------------------------------------*/
// Prototypes for tpool.c

static int create_jobs_queue(int max_jobs);
static int create_worker_thread(int pool_index);
int destroy_thread_pool_resources();
static void *my_little_worker_bee();
int tpool_add_task(int newtask);
int tpool_init(void (*process_task)(int));


/* --------------------------------------------------------------------------------------*/
// Global variables for the thread pool
static queue_object_t jobs_queue;
static tpool_object_t tpool;


/* --------------------------------------------------------------------------------------*/
// Functions for tpool.c


// Called by tpool_init() to create a jobs queue
// Returns 0 on success, -1 on failure
int create_jobs_queue(int max_jobs){
	// Initialize with zero jobs
	if((jobs_queue.queue_buffer = malloc(sizeof(int)*max_jobs)) == NULL){
		fprintf(stderr, "Unable to allocate memory for the job queue.\n");
		return -1;
	}
	jobs_queue.buffer_length = max_jobs;
	jobs_queue.jobs_available = 0;
	jobs_queue.current_job = 0;
	jobs_queue.latest_job = 0;
	pthread_mutex_init(&(jobs_queue.rwlock), NULL);
	pthread_mutex_init(&(jobs_queue.process_lock), NULL);
	return 0;
}

// Called by tpool_init() to create the worker threads
// Accepts a pool index identifier
// Returns 0 on success, -1 on failure
int create_worker_thread(int pool_index){
	// Create a worker thread object
	#ifdef DEBUG
		printf("Creating worker thread #%d.\n", pool_index + 1);
	#endif

	// Create the thread
	pthread_t worker_thread;
	if(pthread_create(&worker_thread, NULL, my_little_worker_bee, NULL) != 0){
		perror("Failure to create a worker thread.\n");
		return -1;	
	}

	#ifdef DEBUG
		printf("Worker thread #%d created.\n", pool_index + 1);
	#endif

	// Worker thread details recorded
	return 0;
}
// End create_worker_thread


// Called by main to destroy thread pool
// The thread pool resources are destroyed when the server process is cancelled.
// Returns 0 on success, -1 on failure
int destroy_thread_pool_resources(){
	// This was not specified in the instructions.

	// TODO: Check if it exists?

	// TODO: Clear jobs

	// TODO: Clear jobs_queue

	// TODO: Clear threads

	// TODO: Clear thread pool

	// TODO: Clear mutexes

	// Thread pool destroyed
	#ifdef DEBUG
		printf("Thread pool destroyed.\n");
	#endif

	return 0;
}
// End of destroy_thread_poo_resources()


// Called by create_worker_thread()
// Returns 0 on success, -1 on failure
void *my_little_worker_bee(){
	// Identify this thread
	#ifdef DEBUG
		printf("Worker %ld is ready to process a task.\n", syscall(SYS_gettid));
	#endif

	// Worker should attempt to do a job
	
	// Find the the next task in the job queue
	// Infinite loop, should always be looking for a new task
	while(1){
		// Get next task, BLOCK until jobs_queue object is available to read from
		// Add a condition variable and mutex here to avoid busy waiting
		pthread_mutex_lock(&jobs_queue.process_lock);
		while(jobs_queue.jobs_available == 0){
			pthread_cond_wait(&jobs_queue.job_count, &jobs_queue.process_lock);
		}
		// Remove from jobs available
		jobs_queue.jobs_available--;
		pthread_mutex_unlock(&jobs_queue.process_lock);

		// Use a mutex to access the job queue
		pthread_mutex_lock(&jobs_queue.rwlock);
		
		// Get file descriptor for next task
		int file_descriptor = jobs_queue.queue_buffer[jobs_queue.current_job];
		// Show task being handled by a worker thread
		#ifdef DEBUG
			printf("Worker %ld is processing task #%d.\n", syscall(SYS_gettid),file_descriptor);
		#endif
		
		// Remove from job queue
		jobs_queue.queue_buffer[jobs_queue.current_job] = -1;
		if(jobs_queue.current_job != jobs_queue.latest_job){			
			// Move to next job on the queue
			jobs_queue.current_job++;
			// Check if current job exceeds boundary
			if(jobs_queue.current_job > jobs_queue.buffer_length - 1){
				// Wrap to start of queue
				jobs_queue.current_job = 0;
			}
		}
		// If this was the last job in the queue, it doesn't matter for the worker thread.  It will continue in an infinite loop.

		// Track remaining jobs for testing
		#ifdef DEBUG
			int available_jobs = jobs_queue.jobs_available;
		#endif

		// Unlock the job queue
		pthread_mutex_unlock(&jobs_queue.rwlock);

		// Check for remaining jobs in queue, send a signal
		// TODO: This may be unnecessary
		if(jobs_queue.jobs_available > 0){
			pthread_cond_broadcast(&jobs_queue.job_count);
		}

		// Call the function to handle the client file descriptor
		// There is no error check for this
		tpool.call_this_function(file_descriptor);

		// Acknowledge task completed
		#ifdef DEBUG
			// Pretend to do something for 5 seconds
			sleep(5);
			printf("Task #%d completed.\n", file_descriptor);
			printf("Tasks Remaining %d.\n", available_jobs);
		#endif
	}
	
	// Should never get here
	exit(EXIT_FAILURE);
}
// End of my_little_worker_bee()


// Called by main to add tasks to the job queue
// Accepts an integer (intended to be a file descriptor)
// Returns 0 on success, -1 on failure
int tpool_add_task(int newtask){
	#ifdef DEBUG
		printf("------------------------------------------------\n");
		printf("Creating task #%d.\n", newtask);
	#endif

	// Lock the job queue.  BLOCK until able to do so.
	pthread_mutex_lock(&jobs_queue.rwlock);

	// Determine next position for a new job
	size_t new_job_at = jobs_queue.latest_job + 1;

	// Check if the buffer is full
	if((size_t)jobs_queue.jobs_available == jobs_queue.buffer_length){
		// Expand the queue
		// Track the current buffer size if needed
		size_t old_buffer_size = jobs_queue.buffer_length;
		jobs_queue.buffer_length = jobs_queue.buffer_length * 2;
		#ifdef DEBUG
			printf("New buffer size? %lu\n", jobs_queue.buffer_length);
		#endif
		int *temp_buffer = realloc(jobs_queue.queue_buffer,sizeof(int)*jobs_queue.buffer_length);
		jobs_queue.queue_buffer = temp_buffer;
		#ifdef DEBUG
			printf ("Expanded the job queue.\n");
		#endif

		// Check if current job is higher than latest job
		if(jobs_queue.current_job > jobs_queue.latest_job){
			// Check where current job is
			if(jobs_queue.current_job == (old_buffer_size - 1)){
				// Move current job to end of the new queue
				jobs_queue.queue_buffer[jobs_queue.buffer_length -1] = jobs_queue.queue_buffer[jobs_queue.current_job];
				jobs_queue.current_job = jobs_queue.buffer_length - 1;
			}
			else{
				// Move jobs to the new buffer space
				size_t new_position = old_buffer_size;
				for(size_t array_index = 0;array_index < jobs_queue.current_job; array_index++){
					new_position = old_buffer_size + array_index;
					jobs_queue.queue_buffer[new_position] = jobs_queue.queue_buffer[array_index];
					jobs_queue.queue_buffer[array_index] = -1;
				}
				new_job_at = new_position + 1;
			}
		}
	}
	else{
		if(jobs_queue.jobs_available == 0){
			// Reset jobs queue
			new_job_at = 0;
			jobs_queue.current_job = 0;
			jobs_queue.queue_buffer[0] = -1;
		}
		else{
			// Get new position for latest job
			new_job_at = ((jobs_queue.latest_job + 1) % jobs_queue.buffer_length);
		}
	}

	// Assign new job
	// Set latest task
	jobs_queue.latest_job = new_job_at;
	jobs_queue.queue_buffer[jobs_queue.latest_job] = newtask;

	#ifdef DEBUG
		printf("Task created for file descriptor #%d.\n", newtask);
	#endif

	// Unlock the job queue
	pthread_mutex_unlock(&jobs_queue.rwlock);

	// Use a mutex to lock job count
	pthread_mutex_lock(&jobs_queue.process_lock);
	// Increment jobs available
	jobs_queue.jobs_available++;
	pthread_mutex_unlock(&jobs_queue.process_lock);
	// Send a signal to condition variable that there is a job in the queue to process
	pthread_cond_broadcast(&jobs_queue.job_count);

	#ifdef DEBUG
		printf("------------------------------------------------\n");
		printf("File descriptor #%d inserted into job queue.\n", newtask);
		printf("Verify tasks in the job queue: %d jobs available.\n", jobs_queue.jobs_available);
		printf("Current Job: %lu\n", jobs_queue.current_job);
		printf("Latest Job: %lu\n", jobs_queue.latest_job);
		printf("------------------------------------------------\n");
	#endif

	// Task added to job que
	return 0;
}
// End of tpool_add_task()


// Begin tpool_init()
// Accepts a function as an argument.  This is the pointer for the worker to handle tasks
// Returns 0 on success, -1 on failure
int tpool_init(void (*process_task)(int)){
	#ifdef DEBUG
		printf("Initialize thread pool.\n");
	#endif

	// Use a system call to determine the number of CPU cores available for thread pool size
	long number_of_available_processing_cores = -1;
	// Determine number of available CPU cores
	if((number_of_available_processing_cores = sysconf(_SC_NPROCESSORS_ONLN)) == -1){
		fprintf(stderr, "Can't determine number of available CPU cores to set thread pool size.\n");
		return -1;
	}
	// Assign to number of threads
	int max_threads = 0;
	// Verify the safe conversion of the number of cores to an int
	if(number_of_available_processing_cores >= INT_MIN && number_of_available_processing_cores <= INT_MAX){
		max_threads = number_of_available_processing_cores;
	}
	else{
		fprintf(stderr, "WARNING: Unable to verify safe conversion of data when determining number of threads.  Default setting of number of threads to a plausibly safe value.\nAssumed Thread Count: 4\n");
		max_threads = 4;
	}
	// Set maximum number of jobs in queue (available threads * tasks per thread + 1)
	int max_jobs_in_queue = max_threads + 1;
	#ifdef DEBUG
		printf("Maximum threads available: %d\n", max_threads);
		printf("Maximum jobs in the queue at start: %d\n", max_jobs_in_queue);
	#endif

	// Store the function to be used by workers
	tpool.call_this_function = process_task;
	#ifdef DEBUG
		printf("Thread pool started.\n");
	#endif

	#ifdef DEBUG
		printf("Creating a job queue for tasks.\n");
	#endif

	// Create the job queue
	if((create_jobs_queue(max_jobs_in_queue))== -1){
		fprintf(stderr, "Problem setting up a jobs queue.\n");
		return -1;
	}

	#ifdef DEBUG
		printf("Job queue created.\n");
		printf("Jobs Available: %d\n", jobs_queue.jobs_available);
	#endif

	#ifdef DEBUG
		printf("Create a place to track worker threads in the pool.\n");
	#endif

	#ifdef DEBUG
		printf("Create worker threads.\n");
	#endif

	// Create attribute object for threads
	pthread_attr_t pthread_attr;
	if(pthread_attr_init(&pthread_attr) != 0 || pthread_attr_setdetachstate(&pthread_attr, PTHREAD_CREATE_DETACHED) != 0){
		perror("Server: Unable to set attribute for threads to detach state.");
		// This is critical because if 1000s of thread control blocks are created and the memory is not reclaimed it can cause problems in the stack
		return -1;
	}

	for(int i = 0; i < max_threads; i++){
		// Create a worker thread and assign to pool index
		if((create_worker_thread(i)) == -1){
			fprintf(stderr, "Unable to create worker threads.\n");
			return -1;		
		}
		printf("Number of Worker Threads Created: %d\n", i + 1);
	}
	#ifdef DEBUG
		printf("Worker threads working ...\n");
	#endif
	// Thread pool up and running, return control to main to aggregate jobs to workers
	return 0;
}