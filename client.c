/* Kirk Powell
 * CS 410/591 - Final Project (Client)
 * May 2, 2016
 * 
 * Compile Using this format:
 * $ gcc client.c -o client.exe
 *
 * $ gcc -Wall -Werror -pedantic client.c -o client.exe -pthread -lrt
 * TODO: Fix compile error on line 385
 *
 * Run from command line interface (CLI):
 * ./client.exe
 *
 * Works with server.c
 *
 * Sources:
 	CS407 Lab Solutions by Kirk Powell
	"The Linux Programming Interface" [2010] by Michael Kerrisk
 	"Beginning Linux Programming" [2008] by Matthew and Stone.
 *
 */

// TODO: Turn this off when submitting for grading
// #define DEBUG 1

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

// Declared Constants
// Set shared secret
#define SECRET "<cs407rembash>\n"
// Set the port to be used
#define PORT 4070
// Set buffer size for pty slave name
#define MAX_SNAME 1000
// Set buffer size for communications between Bash and PTY
#define BUFFER_SIZE 4096

// Declare functions
int configure_client_socket(char *IP_ADDRESS);
void connect_client_to_server(int sockfd);
void relay_command_and_read_server_socket(int sockfd);
void sigchld_handler(int signal);
int tty_set_raw(int fd);

// Global variable for PTY
struct termios ttyOrig;

// Reset terminal mode on program exit
static void ttyReset(void){
	if(tcsetattr(STDIN_FILENO, TCSANOW, &ttyOrig) == -1){
		perror("Client: Unable to resert terminal.");
		exit(EXIT_FAILURE);
	}
}


// Begin main()
int main(int argc, char *argv[]){
	#ifdef DEBUG
		printf("Initializing client ...\n");
	#endif

	char *IP_ADDRESS;
	// Capture command line argument & check for valid ipaddress
	if(argc == 2){
		// Capture IP ADDRESS
		IP_ADDRESS = argv[1];

		// Acknowledge command line input
		#ifdef DEBUG
			printf("Processing command: ./client %s\n", argv[1]);
		#endif
	}
	else{
		// Handle incorrect command line entry
		fprintf(stderr, "Usage: ./client [IP_ADDRESS]\n");
		fprintf(stderr, "Example: ./client 127.0.0.1\n");
		// Terminate client connection
		exit(EXIT_FAILURE);
	}


	#ifdef DEBUG
		printf("Configuring client socket.\n");
	#endif

	// Configure client connection
	int sockfd;
	if((sockfd = configure_client_socket(IP_ADDRESS)) == -1){
		// Terminate client connection
		exit(EXIT_FAILURE);
	}

	#ifdef DEBUG
		printf("Saving terminal settings.\n");
	#endif

	// Retrieve the attributes of the terminal and save them for reference
	if(tcgetattr(STDIN_FILENO, &ttyOrig) == -1){
		perror("Client: Unable to retrieve attributes of the terminal.");
		close(sockfd);
		// Terminate client connection
		exit(EXIT_FAILURE);
	}

	#ifdef DEBUG
		printf("Change to noncanonical mode.\n");
	#endif

	// Set noncanonical mode
	if(tty_set_raw(STDIN_FILENO) == -1){
		fprintf(stderr, "Client: Unable to switch to noncanonical mode.");
		// Terminate client connection
		exit(EXIT_FAILURE);
	}


	#ifdef DEBUG
		printf("Connect client socket to server.\n");
	#endif

	// Connect to server (inlcudes protocol exchange)
	connect_client_to_server(sockfd);

	relay_command_and_read_server_socket(sockfd);

	// Acknowledge client is done
	#ifdef DEBUG
		printf("Closing client socket.\n");
	#endif

	exit(EXIT_SUCCESS);
}
// End of Main


// Functions

// Called by main() to intialize a client socket
// Returns socket file descriptor on success
int configure_client_socket(char *IP_ADDRESS){
	int sockfd;
	struct sockaddr_in address;
	memset(&address, 0, sizeof(address));

	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
		perror("Client: Unable to create a socket.");
		return -1;
	}

	address.sin_family = AF_INET;
	address.sin_port = htons(PORT);

	// Validate IP address
	int check_IP;
	// Use command line argument for IP_ADDRESS here
	if((check_IP = inet_aton(IP_ADDRESS, &address.sin_addr)) == 0){
		fprintf(stderr, "Client: Invalid IP Address.\n");
		return -1;
	}
	else if (check_IP == -1){
		fprintf(stderr, "Client: Unable to convert IP Address.\n");
		return -1;
	}
	else {
		// IP ADDRESS is valid
	}

	// Connect to server
	if(connect(sockfd, (struct sockaddr *)&address, sizeof(address)) == -1){
		perror("Client: Unable to connect to server");
		return -1;
	}

	#ifdef DEBUG
		printf("Client socket configured.\n");
	#endif

	return sockfd;
}
// End of configure_client_socket()


// Called by main() to validate client socket connection to server
void connect_client_to_server(int sockfd){
	int nread, nwrite;
	// Check server protocol
	char *protocol = "<rembash>\n";
	char server_protocol[513];
	if((nread = read(sockfd,server_protocol,512)) == -1){
		perror("Client: Error reading from client.");
		exit(EXIT_FAILURE);
	}
	server_protocol[nread] = '\0';
	if(strcmp(protocol,server_protocol) != 0){
		fprintf(stderr, "Client: Incorrect Protocol.\n");	
		// Terminate client connection
		exit(EXIT_FAILURE);
	}

	// Acknowledge protocol
	#ifdef DEBUG
		printf("Protocol confirmed.\n");
	#endif

	// Send shared secret
	if((nwrite = write(sockfd, SECRET, strlen(SECRET))) == -1){
		perror("Client: Unable to send secret to client.");
		// Terminate client connection
		exit(EXIT_FAILURE);
	}
	
	// Acknowledge secret has been sent
	#ifdef DEBUG
		printf("Sent server secret code.\n");
	#endif

	// Check confirmation from server
	char confirm_protocol[513];
	if((nread = read(sockfd,confirm_protocol,512)) == -1){
		perror("Client: Error reading from client.");
		exit(EXIT_FAILURE);
	}
	confirm_protocol[nread] = '\0';
	if(strcmp(confirm_protocol,"<ok>\n") != 0){
		fprintf(stderr, "Client: Server unable to Confirm Handshake.\n");
		// Terminate client connection
		exit(EXIT_FAILURE);
	}

	// Acknowledge client-server connection
	#ifdef DEBUG
		printf("Connection to server established.\n");
	#endif

	return;
}
// End of connect_client_to_server()


// Called by main() to process command lines and display server socket output
void relay_command_and_read_server_socket(int sockfd){
	#ifdef DEBUG
		printf("Set-up signal handler.\n");
	#endif

	struct sigaction act;

	//Setup SIGCHLD handler to deal with child process terminating unexpectedly:
	//(Must be done before fork() in case child immediately terminates.)
	act.sa_handler = sigchld_handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	if (sigaction(SIGCHLD,&act,NULL) == -1) {
		perror("Client: Error registering handler for SIGCHLD");
		exit(EXIT_FAILURE); }

	#ifdef DEBUG
		printf("Create sub-process to handle command line inputs.\n");
	#endif

	int nread, nwrite, total;
	char from_socket[BUFFER_SIZE];
	char command[BUFFER_SIZE];
	// Start a new subprocess to listen to terminal commands and send to PTY
	pid_t read_cpid;
	switch(read_cpid = fork()){
		case -1:
			// Unable to fork, close client
			perror("Client: Error trying to create sub-process to handle terminal commands.");
			// Terminate client connection
			exit(EXIT_FAILURE);
		case 0:
			// Child process to read command lines from terminal
			// Wrtie to closed connection produces an error instead of a signal
			signal(SIGPIPE,SIG_IGN);

			#ifdef DEBUG
				printf("Client sub-process.\n");
			#endif

			// Read from client terminal
			nwrite = 0;
			while(nwrite != -1 && (nread = read(0,command,BUFFER_SIZE)) > 0){
				total = 0;
				do {
					// Write to remote socket
					if((nwrite = write(sockfd,command+total,nread-total)) == -1){
						break;
					}
					total += nwrite;
				} while(total < nread);
			}
			if(errno){
				perror("Client: Error when reading input command.");
			}
			else{
				fprintf(stderr, "Client: Connection to server closed.");
			}

			// Should not get here
			// Terminate client sub-process
			exit(EXIT_FAILURE);
	}
	
	// Client sub-process reading command line inputs from terminal

	// Resume client process

	// Reset terminal when server sub-process terminates
	if(atexit(ttyReset) != 0){
		perror("Client: Unable to reset terminal.");
		// Terminate client connection
		exit(EXIT_FAILURE);
	}


	#ifdef DEBUG
		printf("Client reading from server socket.\n");
	#endif

	// Read input from server to relay to client
	nwrite = 0;
	while(nwrite != -1 && (nread = read(sockfd, from_socket, BUFFER_SIZE)) > 0){
		total = 0;
		do{
			// Write to stdout
			if((nwrite = write(1,from_socket+total,nread-total)) == -1){
				break;
			}
			total += nwrite;
		}while(total < nread);
	}
	if(errno){
		// Parent error reading from buffer
		perror("Client: Unable to read from Bash");
	}			
	
	//Done communicating with remote shell process, so terminate child handling command input:
	//(First, remove SIGCHLD handler and set to be ignored, so don't have to collect child.)
	act.sa_handler = SIG_IGN;
	if (sigaction(SIGCHLD,&act,NULL) == -1)
		perror("Client: Error setting SIGCHLD to be ignored");

	// Termindate child processes
	kill(read_cpid,SIGTERM);
	
	return;
}
// End of relay_command_and_read_server_socket()


// Handler for SIGCHLD:
// Collects child and terminates parent (failure).
// Intended to be called only if child process terminates
// prematurely/unexpectedly due to some error.
void sigchld_handler(int signal)
{
  wait(NULL);
  // restore_tty_settings(&tty_settings);
  exit(EXIT_FAILURE);
}
// End of sigchld_handler


// Called by main() to set noncanonical mode
// Returns 0 on successful confirgurations
int tty_set_raw(int fd){
	struct termios t;

	// Get terminal attributes
	if(tcgetattr(fd, &t) == -1){
		return -1;
	}

	// Check if attributes have already been set
	if(&ttyOrig != NULL){
		ttyOrig = t;
	}

	// From the book: "Noncanonical mode, disables signals, extended input processing, and echoing"
	t.c_lflag &= ~(ICANON | ECHO);

	// Only one character at a time
	t.c_cc[VMIN] = 1;

	// BLOCK!
	t.c_cc[VTIME] = 0;

	// Set new attributes
	if(tcsetattr(fd, TCSAFLUSH, &t) == -1){
		return -1;
	}

	return 0;
}
// End of tty_set_raw()