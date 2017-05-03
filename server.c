/* Kirk Powell
 * CS 410/591 - Final Project (Client)
 * May 2, 2016
 * 
 * Compile Using this format:
 * $ gcc -Wall -Werror -pedantic server.c -o server.exe -pthread -lrt
 *
 * Run from command line interface (CLI):
 * ./server.exe
 *
 * Works with client.c
 * 
 * Sources:
 	CS407 Lab Solutions by Kirk Powell
	"The Linux Programming Interface" [2010] by Michael Kerrisk
 	"Beginning Linux Programming" [2008] by Matthew and Stone.
 *
 */

// TODO: Turn this off when submitting for grading
#define DEBUG 1

// Feature Test Macro for pseudalterminal device (PTY)
#define _XOPEN_SOURCE 600
// Feature Test Macro for timers
#define _POSIX_C_SOURCE 200809L
// Feature Test Macro for accept4() call
#define _GNU_SOURCE

// Headers
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include "tpool.c"
#include <unistd.h>

// Declared Constants
// Set shared secret
#define SECRET "<cs407rembash>\n"
// Set the port to be used by server and clients
#define PORT 4070
// Set buffer size for pty slave name
#define MAX_SNAME 1000
// Set buffer size for communications between Bash and PTY
#define BUFFER_SIZE 4096
// Set the clock to be used by timer
#define CLOCKID CLOCK_REALTIME
// Set a limit on the epoll
#define MAX_CLIENTS 64000

// Declare functions
int create_pty(char *pty_slave_name);
int create_server_socket();
void destroy_connection(int read_fd);
int handle_client(int client_fd);
void *handle_epoll(void *);
int start_protocol_exchange(int connect_fd);
void relay_data(int file_descriptor);
void run_pty_shell(char *pty_slave_name);
int set_socket_to_non_block(int socket_fd);
void signal_handler(int sig, siginfo_t *si, void *uc);

// Global variables
pid_t cpid_list[MAX_CLIENTS] = { 0 };
// File descriptor for epoll
int epoll_fd;
// Pairs of file descriptors for epoll to scan.  All initialized to 0
int epoll_fd_pairs[MAX_CLIENTS * 2 + 5] = { -1 };
// Client status check
// 0 : Uninitialized
// 1 : Client is attempting protocol exchange
// 2 : Client is sending input
int client_status_record[MAX_CLIENTS] = { -1 };

// Begin main()
int main(){
	#ifdef DEBUG
		printf("Starting server ...\n");
	#endif

	int server_sockfd, client_sockfd;
	pthread_t epoll_thread;

	// Call create_server_socket()
	if((server_sockfd = create_server_socket()) == -1){
		perror("Server: Unable to instantiate the server socket.");
		exit(EXIT_FAILURE);
	}

	// Ignore when a child process closes
	signal(SIGCHLD, SIG_IGN);
	// Ensure write to a closed socket doesn't terminate server
	signal(SIGPIPE,SIG_IGN);

	#ifdef DEBUG
		printf("Server preparing ePoll API ...\n");
	#endif

	// Create epoll API
    if((epoll_fd = epoll_create1(EPOLL_CLOEXEC)) == -1){
        perror("Server: Unable to create ePoll API.");
        exit(EXIT_FAILURE);
    }

	// Set up epoll API to handle read/writes
	if(pthread_create(&epoll_thread, NULL, handle_epoll, NULL) != 0){
		perror("Server: Unable to set-up ePoll API.");
		exit(EXIT_FAILURE);
	}

	// Setup handler for signals to terminate a connection if it exceeds the timer limit
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = &signal_handler;
	sigaction(SIGRTMAX, &sa, NULL);

	// Establish a thread pool
	// Call tpool_init() to create a thread pool
	// Pass a function as an argument
	if(tpool_init(relay_data) == -1){
		fprintf(stderr, "Unable to initialize a thread pool.\n");
		exit(EXIT_FAILURE);
	}

	// Begin accepting new clients
	#ifdef DEBUG
		printf("Server waiting ...\n");
	#endif

	// Begin listening on the socket
	while(1){
		// Important!! --> Server blocks on accept4() call.
		// Do not make client socket non-blocking until after protocol exchange
		if((client_sockfd = accept4(server_sockfd, (struct sockaddr *) NULL, NULL, SOCK_CLOEXEC)) != -1){
			// Check for maximum clients
			if(client_sockfd >= MAX_CLIENTS * 2 + 5){
				close(client_sockfd);
				break;
			}

			#ifdef DEBUG
				printf("Processing new client ...\n");
			#endif

			// Initiate protocol exchange
			// Set client status incase it was not cleared
			client_status_record[client_sockfd] = 0;
			relay_data(client_sockfd);

			// Notify server and continue listening for new clients
			#ifdef DEBUG
				printf("Server waiting ...\n");
			#endif
		}
		// Slow it down for debugging
		#ifdef DEBUG
			sleep(1);
		#endif
	}
	// This is an infinite loop
	// CTRL-C in the terminal will stop the server from running

	// Should never get here ...
	exit(EXIT_FAILURE);
}
// End of Main



// Functions


// Called by handle_client() to create pty device for client
// Stores the pty slave name and returns the master file descriptor on success
// Must store pty_slave_name for use by other functions
int create_pty(char *pty_slave_name){
	// Open PTY master device
	int master_fd;
	char *p;

	if((master_fd = posix_openpt(O_RDWR | O_CLOEXEC)) == -1){
		fprintf(stderr, "Server: Could not create pseudoterminal.");
		return -1;
	}

	// Set pty master to non-blocking
	if(set_socket_to_non_block(master_fd) == -1){
		fprintf(stderr, "Server: Unable to set client socket to non-blocking");
		pthread_exit(NULL);
	}

	// Unlock PTY slave
	// Error check not needed here because it can only fail if file descriptor is an error
	unlockpt(master_fd);

	// Get PTY slave name
	p = ptsname(master_fd);
	if(p == NULL){
		return -1;	
	}

	if(strlen(p) < MAX_SNAME){
		strncpy(pty_slave_name,p,MAX_SNAME);
	}
	else{
		errno = EOVERFLOW;
		return -1;	
	}

	return master_fd;
}
// End of create_pty()


// Called by main server loop to create a server socket
// Returns a server socket file descriptor on success
int create_server_socket(){
	int server_sockfd;
	int optval = 0; // Used in setsockopt to disable argument
	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(server_address));
	
	// Create server socket
	// Need sock_cloexec here
	if((server_sockfd = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0)) == -1){
		perror("Server: Unable to create server socket.");
		return -1;
	}

	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = htonl(INADDR_ANY);
	server_address.sin_port = htons(PORT);

	// Allow kernel to begin using the port again when server terminated
	if(setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1){
		perror("Server: Unable to inform kernel to reuse server socket.");
		return -1;
	}

	// Bind socket to server
	if(bind(server_sockfd, (struct sockaddr *)&server_address, sizeof(server_address)) == -1){
		perror("Server: Unable to bind socket to server.");
		return -1;
	}

	// Assign server to listen on the socket
		// $ man listen
		// If the backlog argument is greater than the value in
		// /proc/sys/net/core/somaxconn, then it is silently truncated to that
		// value; the default value in this file is 128.  In kernels before
		// 2.4.25, this limit was a hard coded value, SOMAXCONN, with the value
		// 128.
	if(listen(server_sockfd, 128) == -1){
		perror("Server: Unable to listen on server socket.");
		return -1;
	}

	return server_sockfd;
}
// End of create_server_socket


// Called by epoll loop
// Accepts a client socket file descriptor
void destroy_connection(int read_fd){
	// Find the client socket pair
	int write_fd = epoll_fd_pairs[read_fd];

	#ifdef DEBUG
		printf("Problem handling client.  Closing file descriptors %d and %d\n", read_fd, write_fd);
	#endif

	// Need to remove client file descriptor pair from epoll event list
	struct epoll_event ev;
	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = read_fd;
	epoll_ctl(epoll_fd,EPOLL_CTL_DEL,read_fd,&ev);
	ev.data.fd = write_fd;
	epoll_ctl(epoll_fd,EPOLL_CTL_DEL,write_fd,&ev);

	// Should be closed by epoll API, but just in case ...
	close(read_fd);
	close(write_fd);
}

// Called by relay_data() to handle client connection
// Accepts the socket file descriptor assigned to the client: connect_fd
// Returns 0 on success, -1 on failure
int handle_client(int connect_fd){
	int master_fd;
	char pty_slave_name[MAX_SNAME];
	// To add to the interest list
	struct epoll_event evlist[2];
	memset(&evlist, 0, sizeof(evlist));
	// Store Bash pid
	pid_t cpid;
	// Confirmation for client when connection established
	char *write_error = "<error>\n";
	char *confirm_protocol = "<ok>\n";
	char from_client[513];
	int nread = 0;
	int nwrite = 0;

	// Verify client shared secret
	if((nread = read(connect_fd,from_client,512)) == -1){
		perror("Server: Error reading from client.");
		return -1;
	}
	from_client[nread] = '\0';
	if(strcmp(from_client, SECRET) != 0){
	    // Notify client of error
		if((nwrite = write(connect_fd, write_error, strlen(write_error))) == -1){
			perror("Server: Error notifying client of incorrect shared secret.");
			return -1;
		}

		// Acknowledge client rejected
		#ifdef DEBUG
			printf("Token rejected for client file descriptor %d.\n", connect_fd);
		#endif

		return -1;
	}

	// Turn off the signal notification after protocol exchange
	signal(SIGRTMAX, SIG_IGN);

	// // Destroy timer
	// TODO: Figure out how to destroy the timer
	// if(timer_delete(timer_id) == -1){
	// 	fprintf(stderr, "Server: Timer is still available for %d", connect_fd);
	// 	// If timer is not deleted, it is a resource problem that shouldn't prevent collapse of the connection
	// }

	// Confirm new client and create a pseudoterminal
	#ifdef DEBUG
		printf("Create PTY for client with file descriptor %d.\n", connect_fd);
	#endif

	// Set client socket to non-blocking
	if(set_socket_to_non_block(connect_fd) == -1){
		fprintf(stderr, "Server: Unable to set client socket to non-blocking");
		return -1;
	}

	// Create pseudoterminal for bash to execute on
	if((master_fd = create_pty(pty_slave_name)) == -1){
		perror("Server: Unable to create PTY. Cancelled client connection.");
		return -1;
	}

	#ifdef DEBUG
		printf("PTY Created.  Start sub-process for Bash to be executed in.\n");
	#endif

	// Create a sub-process to handle Bash on a pseudoterminal
	switch(cpid = fork()){
		case -1:
			perror("Server: Unable to create sub-process for Bash to execute in.");
			return -1;
		case 0:
			// This is creating a sub-process with inheritance of file descriptors
			#ifdef DEBUG
				printf("Server sub-process for Bash.\n");
			#endif

			// The PTY Master file descriptor is not needed in the server sub-process
			// Handle open sockets
			close(connect_fd);
			close(master_fd);

			// Do stuff and then exec Bash
			run_pty_shell(pty_slave_name);

			// If Bash failed, terminate server sub-process, file descriptors get erased on exit
			exit(EXIT_FAILURE);			
	}

	// Bash executing in new sub-process with pseudoterminal
	// Return of control flow to server thread

	// Register client file descriptors in global scope
	epoll_fd_pairs[master_fd] = connect_fd;
	epoll_fd_pairs[connect_fd] = master_fd;
	// Add sub-process identifier here so ePoll can terminate on error
	cpid_list[master_fd] = cpid;
	cpid_list[connect_fd] = cpid;

	#ifdef DEBUG
		printf("Master FD: %d\n", master_fd);
		printf("Connect FD: %d\n", connect_fd);
		printf("epoll_fd_pairs[%d]: %d\n", epoll_fd_pairs[master_fd],epoll_fd_pairs[connect_fd]);
		printf("epoll_fd_pairs[%d]: %d\n", epoll_fd_pairs[connect_fd],epoll_fd_pairs[master_fd]);
	#endif

	// Add bash relay file descriptor to epoll
	evlist[0].events = EPOLLIN;
	evlist[0].data.fd = master_fd;
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, master_fd, evlist) == -1){
	    perror("Server: Unable to add Master FD to ePoll interest list.");
	    return -1;
	}

	// Confirm shared secret
	if((nwrite = write(connect_fd, confirm_protocol, strlen(confirm_protocol))) == -1){
		perror("Server: Error notifying client of confirmed shared secret.");
		return -1;
	} 

	// Increment client status to ready IO
	client_status_record[connect_fd] = 2;
	client_status_record[master_fd] = 2;

	#ifdef DEBUG
		printf("Client-Server Protocol Exchange Completed.\n");
	#endif

	return 0;
}
// End of handle_client()


// Called by main server loop to handle ePoll API
void *handle_epoll(void * _){
	#ifdef DEBUG
		printf("Server ePoll API started.\n");
	#endif
	
	// Large enough to handle two file descriptors for each client
	struct epoll_event evlist[MAX_CLIENTS * 2];
	memset(&evlist, 0, sizeof(evlist));
   	int ready_fds = 0;
   	int j = 0;

    // Find file desciptors with needs
    while(1){
    	#ifdef DEBUG
	        printf("Starting ePoll event tracking loop.\n");
	    #endif

	    // Create epoll interest list from global variable
	    // Calculate how many file descriptors are ready
	    ready_fds = 0;
	    // Clear the value in errno
	    errno = 0;
	    // Since a single thread is handling the io, it is unnecessary to get more than one set of file descriptors to handle here
        ready_fds = epoll_wait(epoll_fd, evlist, 2, -1);
        if (ready_fds == -1) {
        	// Handle signal interruptions
            if (errno == EINTR){
                continue;
            }
            else{
            	// Terminate server on any other error
        		perror("Server: Problem with ePoll interest list.");
		        exit(EXIT_FAILURE);
            }
        }

	    #ifdef DEBUG
	        printf("Need to Handle: %d\n", ready_fds);
	    #endif

	    // Process ready file descriptors
        for (j = 0; j < ready_fds; j++){
            if(evlist[j].events & EPOLLIN){
            	// Add task to the queue using the thread pool
				if(tpool_add_task(evlist[j].data.fd) == -1){
					fprintf(stderr, "Adding task #%d failed.\n", evlist[j].data.fd);
				}
			}
			else if(evlist[j].events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)){
				#ifdef DEBUG
					printf("Server: EPOLLHUP, EPOLLERR, or EPOLLRDHUP.\n.");
				#endif
				int read_from_socket = evlist[j].data.fd;
				destroy_connection(read_from_socket);
			}
			// Any other condition for the event will be ignored here
        }
        #ifdef DEBUG
	        sleep(1);
	    #endif
    }

    // epoll thread is an infinite loop

    // Should only get here if there is a failure in the server
    fprintf(stderr, "WARNING. All file descriptors are closed.\n");

	// Terminate ePoll API
	pthread_exit(NULL);
	// Terminate server since there is no epoll API
	exit(EXIT_FAILURE);
}
// End of handle_epoll()


// Called by relay_data() to initiate protocol exchange with server
// Accepts the socket file descriptor assigned to the client: connect_fd
// Returns 0 on success, -1 on failure
int start_protocol_exchange(int connect_fd){
	// Start a timer to limit protocol exchange
	struct itimerspec ts;
	memset(&ts, 0, sizeof(ts));

	struct sigevent sevp;
	memset(&sevp, 0, sizeof(sevp));

	timer_t timer_id;
	int nwrite = 0;
	// Prevent this value or the pointer from being changed
	const char * const server_protocol = "<rembash>\n";

	// Timer need only expire once
	ts.it_interval.tv_sec = 0;
	ts.it_interval.tv_nsec = 0;
	// Timer should be 5 seconds
	ts.it_value.tv_sec = 5;
    ts.it_value.tv_nsec = 0;

    // Notify by thread
	sevp.sigev_notify = SIGEV_THREAD_ID;
	sevp.sigev_signo = SIGRTMAX;
	sevp._sigev_un._tid = syscall(SYS_gettid);
	sevp.sigev_value.sival_int = connect_fd;

    // Create a timer to limit protocol exchange
    if(timer_create(CLOCKID, &sevp, &timer_id) == -1){
    	if(errno == EINVAL){
    		perror("Server: Invalid Inputs: Clock ID, Signal Structure or Timer ID");
    	}
    	else if (errno == ENOMEM){
    		perror("Server: Could not allocate memory");
    	}
    	else if (errno == EAGAIN){
    		perror("Server: Kernel Allocation");
    	}
    	else{
	    	perror("Server: Unable to create a timer for protocol exchange.");
	    }
    	return -1;
    }

	// Send server protocol to client		
	if((nwrite = write(connect_fd, server_protocol, strlen(server_protocol))) == -1){
		perror("Server: Unable to communicate protocol to client.");
		return -1;
	}

    // Activate the timer after sending initial protocol
    // This will allow the client 5 seconds to respond with a correct shared secret
    if(timer_settime(timer_id, 0, &ts, NULL) == -1){
       	perror("Server: Unable to start timer for protocol exchange.");
    	return -1;	
    }

	// Increment client status
	client_status_record[connect_fd] = 1;

	// To add to the interest list
	struct epoll_event evlist[2];
	memset(&evlist, 0, sizeof(evlist));

	// Add client file descriptors to epoll	
	evlist[0].events = EPOLLIN;
	evlist[0].data.fd = connect_fd;
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, connect_fd, evlist) == -1){
	    perror("Server: Unable to add to ePoll interest list.");
	    return -1;
	}

	// Protocol exchange initiated
	return 0;
}
// End of start_protocol_exhcange()


// Called by thread pool workers to handle the io
// Accepts the socket file descriptor assigned to the client: connect_fd
void relay_data(int file_descriptor){
   	int nread = 0;
   	int nwrite = 0;
   	int total = 0;
	char buffer[BUFFER_SIZE];
	// Determine where to read from and where to write to
	int	read_from_socket = file_descriptor;
	int	write_to_socket = epoll_fd_pairs[read_from_socket];

	// Check client status for protocol exchange
	switch(client_status_record[file_descriptor]){
		case 0:
			if((start_protocol_exchange(file_descriptor)) == -1){
				fprintf(stderr, "Server: Unable to initiate protocol exchange.\n");
			    destroy_connection(file_descriptor);
			}
			break;
		case 1:
			if((handle_client(file_descriptor)) == -1){
				fprintf(stderr, "Server: Unable to complete setup for client.\n");
				destroy_connection(file_descriptor);
			}
			break;
		case 2:
			// Handle client IO
			errno = 0;
			if((nread = read(read_from_socket,buffer,BUFFER_SIZE)) > 0){
			 	total = 0;
			 	do{
					if((nwrite = write(write_to_socket,buffer+total,nread-total)) == -1){
						break;
					}
					total += nwrite;
					// Keep reading from the buffer until it is done
				}while(total < nread);
			}

			// Handle errors from io
			// TODO: Handle this error check without crashing the connection
			// if(nread == 0  || errno){
			// 	perror("Server: Unable to read output.");
			// 	// Close the file descriptors on error
			// 	destroy_connection(read_from_socket);
			// }
			break;
		default:
			// This can only occur from an error
			// TODO: Error check this situation
			break;
	}
}
// End relay_data()

// Called by handle_client() to run PTY shell [This is where BASH executes!]
void run_pty_shell(char *pty_slave_name){
	// Child is the leader of the new session and looses its controlling terminal.
	if(setsid() == -1){
		perror("Server: Unable to set a new session.");
		exit(EXIT_FAILURE);
	}

	// Set PTY slave as the controlling terminal
	int slave_fd;
	if((slave_fd = open(pty_slave_name, O_RDWR)) == -1){
		perror("Server: Unable to set controlling terminal.");
		exit(EXIT_FAILURE);
	}

	#ifdef DEBUG
		printf("Server sub-process ready to execute Bash.\n");
	#endif

	// Child process needs redirection
	// stdin, stdout, stderr must be redirected to client connection socket
	if(dup2(slave_fd, STDIN_FILENO) != STDIN_FILENO){
		perror("Server: Unable to redirect standard input.");
		exit(EXIT_FAILURE);
	}
	if(dup2(slave_fd, STDOUT_FILENO) != STDOUT_FILENO){
		perror("Server: Unable to redirect standard output.");
		exit(EXIT_FAILURE);
	}
	if(dup2(slave_fd, STDERR_FILENO) != STDERR_FILENO){
		perror("Server: Unable to redirect standard error output.");
		exit(EXIT_FAILURE);
	}

	// Start Bash
	execlp("bash", "bash", NULL);

	// Handle error code from Bash failure
	// Terminate the sub-process intended to handle bash for the client
	perror("Server: Unable to execute Bash in terminal.");
	exit(EXIT_FAILURE);
}
// End of run_pty_shell()


// Called by handle_client and create_pty to set non-blocking io
// Returns 0 on success, -1 on failure
int set_socket_to_non_block(int socket_fd){
	// Get bitmask for the socket
	int flag_for_fd = 0;
	if((flag_for_fd = fcntl(socket_fd,F_GETFL, 0)) == -1){
		perror("Server: Unable to get socket flags.");
		return -1;
	}
	// Set flag for the file descriptor to non blocking
	if(fcntl(socket_fd, F_SETFL, flag_for_fd | O_NONBLOCK) == -1){
		perror("Server: Unable to set socket to non-blocking.");
		return -1;
	}

	return 0;
}
// End of set_socket_to_non_block


// Handle signals during protocol exchange
void signal_handler(int sig, siginfo_t *si, void *uc){
	#ifdef DEBUG
		printf("Signal Called! Timer expired ...\n");
	#endif

	// Find client socket
	int client_socket = si->si_value.sival_int;
	// Close the file descriptors on error
	destroy_connection(client_socket);

	#ifdef DEBUG
		printf("Closed Client Socket: %d\n", client_socket);
	#endif
}
// End of signal_handler()