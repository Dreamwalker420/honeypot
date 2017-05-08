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
// #define DEBUG 1

// Debug specific to the logfile
// TODO: Turn this off when submitting for grading
#define DEBUGLOG 1

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
// Set the maximum number of events for epoll to handle
#define MAX_EVENTS 15
// Set the clock to be used by timer
#define CLOCKID CLOCK_REALTIME
// Set a limit on the epoll
#define MAX_CLIENTS 64000

// Declare functions
int create_pty(char *pty_slave_name);
int create_server_socket();
void *handle_client(void *arg);
void *handle_epoll(void *);
int protocol_exchange(int connect_fd);
void run_pty_shell(char *pty_slave_name, int connect_fd);
int set_socket_to_non_block(int socket_fd);
void signal_handler(int sig, siginfo_t *si, void *uc);
void write_to_log(char *write_sentence);

// Global variables
pid_t cpid_list[MAX_CLIENTS] = { 0 };
// File descriptor for epoll
int epoll_fd;
// Pairs of file descriptors for epoll to scan.  All initialized to 0
int epoll_fd_pairs[MAX_CLIENTS * 2 + 5] = { 0 };


// Begin main()
int main(){
	#ifdef DEBUG
		printf("Starting server ...\n");
	#endif

	int server_sockfd, client_sockfd;
	pthread_t epoll_thread, client_thread;

	// Call create_server_socket()
	if((server_sockfd = create_server_socket()) == -1){
		perror("Server: Unable to instantiate the server socket.");
		exit(EXIT_FAILURE);
	}

	// Ignore when a child process closes
	if(signal(SIGCHLD, SIG_IGN) == SIG_ERR){
		perror("Server: Unable to ignore children.");
		exit(EXIT_FAILURE);
	}

	#ifdef DEBUG
		printf("Server preparing ePoll API ...\n");
	#endif

	// Create epoll API
    if((epoll_fd = epoll_create1(EPOLL_CLOEXEC)) == -1){
        perror("Server: Unable to create ePoll API.");
        exit(EXIT_FAILURE);
    }

	// Set up epoll API to handle read/writes
	if(pthread_create(&epoll_thread, NULL, &handle_epoll, NULL) != 0){
		perror("Server: Unable to set-up ePoll API.");
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
			// Notify server and continue listening for new clients
			#ifdef DEBUG
				printf("Processing new client ...\n");
			#endif

			#ifdef DEBUGLOG
				printf("Processing new client ...\n");
			#endif

			// Record access attempt
		    char message[255] = "Client initiated contact\n\0";
		    write_to_log(message);

			// A successful client should create a thread to handle the client and return the server to continue listening for another connection.
			// Start a thread to handle the client ONLY if new client was accepted
			// Use a thread to handle the client

			// Need to pass the client socked to the thread function
			int *fd_ptr = malloc(sizeof(int));
			*fd_ptr = client_sockfd;
			if(pthread_create(&client_thread, NULL, &handle_client, fd_ptr) != 0){
				perror("Server: Unable to create thread for handling a client.");
			}

			// Ignore client thread
			if(pthread_detach(client_thread) != 0){
				perror("Server: Unable to detach thread, Kernel still listening for it..");
			}

			// Continue to accept new clients
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
	struct sockaddr_in server_address;
	int i = 1;

	// Create server socket
	if((server_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
		perror("Server: Unable to create server socket.");
		return -1;
	}

	// Carver uses this in lab #2 solution
	// Set up server adress struct, zero-out anything that might be there
	memset(&server_address,0,sizeof(server_address));

	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = htonl(INADDR_ANY);
	server_address.sin_port = htons(PORT);

	// Allow kernel to begin using the port again when server terminated
	if(setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)) == -1){
		perror("Server: Unable to inform kernel to reuse server socket.");
		return -1;
	}

	// Disable Nagle buffer algorithm, speed up transfer
	if(setsockopt(server_sockfd, IPPROTO_TCP, TCP_NODELAY, &i, sizeof(i)) == -1){
		perror("Server: Problem with TCP setting.");
		return -1;
	}

	// Bind socket to server
	if(bind(server_sockfd, (struct sockaddr *)&server_address, sizeof(server_address)) == -1){
		perror("Server: Unable to bind socket to server.");
		return -1;
	}

	// Assign server to listen on the socket
	if(listen(server_sockfd, 10) == -1){
		perror("Server: Unable to listen on server socket.");
		return -1;
	}

	return server_sockfd;
}
// End of create_server_socket


// Called by main server loop to handle client connections
// The socket file descriptor assigned to the client is connect_fd
void *handle_client(void *arg){
	int master_fd;
	char pty_slave_name[MAX_SNAME];
	// Decode client socket file descriptor
	int connect_fd = *(int*)arg;
	free(arg);
	// To add to the interest list
	struct epoll_event evlist[2];
	// Store Bash pid
	pid_t cpid;

	// Call protocol_exchange()
	if(protocol_exchange(connect_fd) == -1){
		fprintf(stderr, "Server: Unable to complete protocol exchange with client.");
		pthread_exit(NULL);
	}

	// Confirm new client and create a pseudoterminal
	#ifdef DEBUG
		printf("Client-Server Protocol Exchange Completed.\n");
		printf("Create PTY for client with file descriptor %d.\n", connect_fd);
	#endif

	// Set client socket to non-blocking
	if(set_socket_to_non_block(connect_fd) == -1){
		fprintf(stderr, "Server: Unable to set client socket to non-blocking");
		pthread_exit(NULL);
	}

	// Create pseudoterminal for bash to execute on
	if((master_fd = create_pty(pty_slave_name)) == -1){
		perror("Server: Unable to create PTY. Cancelled client connection.");
		pthread_exit(NULL);
	}

	#ifdef DEBUG
		printf("PTY Created.  Start sub-process for Bash to be executed in.\n");
	#endif

	// Create a sub-process to handle Bash on a pseudoterminal
	switch(cpid = fork()){
		case -1:
			perror("Server: Unable to create sub-process for Bash to execute in.");
			exit(EXIT_FAILURE);
		case 0:
			// This is creating a sub-process with inheritance of file descriptors
			#ifdef DEBUG
				printf("Server sub-process for Bash.\n");
			#endif

			// The PTY Master file descriptor is not needed in the server sub-process
			close(master_fd);

			// Do stuff and then exec Bash
			run_pty_shell(pty_slave_name, connect_fd);

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

	// Add client file descriptors to epoll	
	evlist[0].events = EPOLLIN;
	evlist[0].data.fd = connect_fd;
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, connect_fd, evlist) == -1){
	    perror("Server: Unable to add to ePoll interest list.");
		pthread_exit(NULL);
	}

	// Add bash relay file descriptor to epoll
	evlist[1].events = EPOLLIN;
	evlist[1].data.fd = master_fd;
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, master_fd, evlist + 1) == -1){
	    perror("Server: Unable to add to ePoll interest list.");
		pthread_exit(NULL);
	}

	// Terminate server thread for handling client connection
	pthread_exit(NULL);
}
// End of handle_client()


// Called by main server loop to handle ePoll API
void *handle_epoll(void * _){
	#ifdef DEBUG
		printf("Server ePoll API started.\n");
	#endif
	
	struct epoll_event evlist[MAX_EVENTS];
    char buffer[BUFFER_SIZE];
   	int nread = 0;
   	int nwrite = 0;
   	int total = 0;
   	int read_from_socket = 0;
   	int write_to_socket = 0;

    // Find file desciptors with needs
    while(1){
    	#ifdef DEBUG
	        printf("Starting ePoll event tracking loop.\n");
	    #endif

	    // Create epoll interest list from global variable
	    // Calculate how many file descriptors are ready
	    int ready_fds = 0;
        ready_fds = epoll_wait(epoll_fd, evlist, MAX_EVENTS, -1);
        if (ready_fds == -1) {
            if (errno == EINTR)
                continue;               /* Restart if interrupted by signal */
            else{
        		perror("Server: Problem with ePoll interest list.");
		        exit(EXIT_FAILURE);
            }
        }

	    #ifdef DEBUG
	        printf("Need to Handle: %d\n", ready_fds);
	    #endif

	    // Process ready file descriptors
        for (int j = 0; j < ready_fds; j++){
            if(evlist[j].events & EPOLLIN){
             	// Determine where to read from and where to write to
             	read_from_socket = evlist[j].data.fd;
            	write_to_socket = epoll_fd_pairs[read_from_socket];

            	// Handle read/write
				nwrite = 0;
				while(nwrite != -1 && (nread = read(read_from_socket,buffer,BUFFER_SIZE)) > 0){
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
				if(errno != EWOULDBLOCK && errno != EAGAIN){
					perror("Server: Unable to read output.");
					// Kill Bash if there is an error here
					kill(cpid_list[evlist[j].data.fd], SIGTERM);
					// Close the file descriptors on error
					if(close(epoll_fd_pairs[read_from_socket]) == -1){
						fprintf(stderr, "Server: Problem closing socket: %d", epoll_fd_pairs[read_from_socket]);
					}
					if(close(epoll_fd_pairs[write_to_socket]) == -1){
						fprintf(stderr, "Server: Problem closing socket: %d", epoll_fd_pairs[write_to_socket]);
					}
			        exit(EXIT_FAILURE);
				}
			}
			else if(evlist[j].events & (EPOLLHUP | EPOLLERR)){
				#ifdef DEBUG
					printf("Server: EPOLLHUP or EPOLLERR.  Closing %d and %d\n.",evlist[j].data.fd, epoll_fd_pairs[evlist[j].data.fd]);
				#endif
				// Close the file descriptors on error
				if(close(epoll_fd_pairs[read_from_socket]) == -1){
					fprintf(stderr, "Server: Problem closing socket: %d", epoll_fd_pairs[read_from_socket]);
				}
				if(close(epoll_fd_pairs[write_to_socket]) == -1){
					fprintf(stderr, "Server: Problem closing socket: %d", epoll_fd_pairs[write_to_socket]);
				}
			}
			else {
				// Should not be possible to get here!
				perror("Server: ePoll API error.");
				// Kill Bash if there is an error here
				kill(cpid_list[evlist[j].data.fd], SIGTERM);
				// Close the file descriptors on error
				if(close(epoll_fd_pairs[read_from_socket]) == -1){
					fprintf(stderr, "Server: Problem closing socket: %d", epoll_fd_pairs[read_from_socket]);
				}
				if(close(epoll_fd_pairs[write_to_socket]) == -1){
					fprintf(stderr, "Server: Problem closing socket: %d", epoll_fd_pairs[write_to_socket]);
				}
		        exit(EXIT_FAILURE);
			}
        }
        #ifdef DEBUG
	        sleep(1);
	    #endif
    }

    #ifdef DEBUG
	    printf("All file descriptors closed.\n");	
	#endif

	// Terminate ePoll API
	pthread_exit(NULL);
}
// End of handle_epoll()


// Called by handle_client() for protocol exchange with server
// Returns 0 on successful protocol exchange
int protocol_exchange(int connect_fd){
	// Start a timer to limit protocol exchange
	struct itimerspec ts;
	struct sigaction sa;
	struct sigevent sevp;
	timer_t timer_id;
	int nread = 0;
	int nwrite = 0;
	char from_client[513];
	char *server_protocol = "<rembash>\n";
	char *write_error = "<error>\n";
	char *confirm_protocol = "<ok>\n";

	// Timer need only expire once
	ts.it_interval.tv_sec = 0;
	ts.it_interval.tv_nsec = 0;
	// Timer should be 5 seconds
	ts.it_value.tv_sec = 5;
    ts.it_value.tv_nsec = 0;

	// Sends signal to terminate if it exceeds the timer limit
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = &signal_handler;
	sigemptyset(&sa.sa_mask);
	if(sigaction(SIGRTMAX, &sa, NULL) == -1){
		perror("Server: Unable to handle signal from timer expiration.");
		return -1;
	}

    // Notify by thread
	sevp.sigev_notify = SIGEV_THREAD_ID;
	sevp.sigev_signo = SIGRTMAX;
	sevp._sigev_un._tid = syscall(__NR_gettid);
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

    // Activate the timer
    if(timer_settime(timer_id, 0, &ts, NULL) == -1){
       	perror("Server: Unable to start timer for protocol exchange.");
    	return -1;	
    }

	// Send server protocol to client		
	if((nwrite = write(connect_fd, server_protocol, strlen(server_protocol))) == -1){
		perror("Server: Unable to communicate protocol to client.");
		return -1;
	}

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
			printf("Client Token Rejected.\n");
		#endif

		return -1;
	}

	// Confirm shared secret
	if((nwrite = write(connect_fd, confirm_protocol, strlen(confirm_protocol))) == -1){
		perror("Server: Error notifying client of confirmed shared secret.");
		return -1;
	} 

	// Turn off the signal notification after protocol exchange
	if(signal(SIGRTMAX, SIG_IGN) == SIG_ERR){
		perror("Server: Unable to turn off signal notification.");
		return -1;
	}

	// Destroy timer
	if(timer_delete(timer_id) == -1){
		fprintf(stderr, "Server: Timer is still active for %d", connect_fd);
		return -1;
	}

	// Protocol exchange completed
	return 0;
}
// End of protocol exhcange


// Called by handle_client() to run PTY shell [This is where BASH executes!]
void run_pty_shell(char *pty_slave_name, int connect_fd){
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
		printf("Signal Called!\n");
	#endif

	// Find client socket
	int client_socket = si->si_value.sival_int;
	// Close client socket
	if(close(client_socket) == -1){
		fprintf(stderr, "Server: Problem closing client socket: %d", client_socket);
	}

	#ifdef DEBUG
		printf("Closed Client Socket: %d\n", client_socket);
	#endif

	// Terminate this thread
	pthread_exit(NULL);

	// Should not print here if successfully exited
	#ifdef DEBUG
		fprintf(stderr, "Thread Not Terminated\n");
	#endif
}
// End of signal_handler()


// Called from anywhere to record information
// Pass a sentence to write to the log file
void write_to_log(char *write_sentence){
	#ifdef DEBUGLOG
		printf("Status: %s\n", write_sentence);
	#endif

    // Set a file pointer
    FILE *fptr;

    // Append to end of file
    fptr = fopen("logfile.txt", "a");

	// http://stackoverflow.com/questions/29539671/correcting-timestamp-on-c-code-log-file#29539790
	char dt[275]; // space enough for DD/MM/YYYY HH:MM:SS and terminator and the 255 for the message
	struct tm tm;
	time_t current_time;

	current_time = time(NULL);
	tm = *localtime(&current_time); // convert time_t to struct tm
	strftime(dt, sizeof dt, "%d/%m/%Y %H:%M:%S ", &tm); // format

   	// Add timestamp
    strcat(dt, write_sentence);

    // Add message
    fprintf(fptr,"%s", dt);

    // Close file descriptor
    fclose(fptr);

}
// End of write_to_log()