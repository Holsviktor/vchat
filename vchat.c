#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>

#define MAX_BUFFER_SIZE 1024
#define MAX_COMMAND_LEN 10
#define MAX_MESSAGE_SIZE 64
#define REC_PORT 6206
#define SEND_PORT 667

static const char whitespaces[2] = {' ', '\n'};

pthread_mutex_t errno_mutex = PTHREAD_MUTEX_INITIALIZER;

void printhelp(char* str);
void *handle_client(void *client);
void *run_server(void *port);
int get_port_from_token(char* str);
void *send_message(void *server_address_ptr, void *message);
int initialize_socket();
void bind_socket(int socket, int port);

int main(int argc, char *argv[])
{
	printf("============================================\n");
	printf("            Welcome to vchat!\n");
	printf("============================================\n");
	printf("Type 'help' to get a list of available commands.\n");
	printf("============================================\n\n");
	static char mode[10] = "vchat";
	static char word[MAX_COMMAND_LEN];
	char inputstring[MAX_BUFFER_SIZE];
	for (;;)
	{
		memset(inputstring,0,MAX_BUFFER_SIZE);
		memset(word,0,MAX_COMMAND_LEN);
		printf("%s > ", mode);	
		errno = 0;
		if (fgets(inputstring,MAX_BUFFER_SIZE-1, stdin) != NULL)
		{
			printf("\n");
		}
		else
		{
			printf("An error occured during input, terminating program.");
			printf("ERROR: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}
		inputstring[MAX_BUFFER_SIZE-1] = '\0';

		char *token = strtok(inputstring, whitespaces);
		if (token != NULL)
		{
			strncpy(word,token,MAX_COMMAND_LEN-1);
			word[MAX_COMMAND_LEN-1] = '\0'; // Ensures that the string ends (NULL termination)
		}
		else
		{
			printf("Line empty\n");
			word[0] = '\0';
		}
		if (strcmp(inputstring, "quit") == 0)
		{
			break;
		}
		else if (strcmp(word, "help") == 0)
		{
			printhelp(inputstring);
		}
		else if (strcmp(word, "testsend") == 0)
		{
			int port_number;
			if ( (port_number = get_port_from_token(inputstring) > 0) )
			{
				send_message_old(port_number);
			}
			else
			{
				printf("Second argument should be an integer greater than 0");
			}
		}
		else if (strcmp(word, "testrecv") == 0)
		{
			run_server_old(30000);
		}
		else if (strcmp(word, "recv") == 0)
		{
			int port_number;
			if ( ((port_number = get_port_from_token(inputstring)) > 0) )
			{
				void *port_pointer = (void *)(intptr_t)port_number;
				run_server(port_pointer);
			}
			else
			{
				printf("Second argument should be an integer greater than 1000.\n");
			}
		}
		else if (strcmp(word,"send") == 0)
		{
			char *ip_address;
			struct sockaddr_in server_address;
			memset(&server_address, 0, sizeof(server_address));
			server_address.sin_family = AF_INET;

			if ( (ip_address = strtok(NULL, whitespaces) ) == NULL)
			{
				printf("Second argument should be an IPv4 address.");
				continue;
			}
			if (strcmp(ip_address, "loopback") == 0)
			{
				ip_address = "127.0.0.1";
			}
			if (inet_pton(AF_INET, ip_address, &server_address.sin_addr) <= 0)
			{
				printf("Enter a valid IPv4 address.\n");
				continue;
			}	
			int port_number;
			if ( ((port_number = get_port_from_token(inputstring)) < 1) )
			{
				printf("Second argument should be an integer greater than 0");
				continue;
			}
			printf("port number: %d\n", port_number);
			server_address.sin_port = htons(port_number);
			
			char m[MAX_MESSAGE_SIZE] = "";
			char *message_token = strtok(NULL,"");
			if (message_token == NULL)
			{
				printf("Remember to add a message.");
				continue;
			}
			strncpy(m,message_token,MAX_MESSAGE_SIZE-1);
			m[MAX_MESSAGE_SIZE-1] = '\0';

			send_message( (void *) &server_address, (void *) m);


		}
		else
		{
			printf("Unrecognized command\n\n");
		}
	}
	
	
	return 0;
}

int get_port_from_token(char* str)
{
	char port_string[MAX_COMMAND_LEN] = "";
	char *port_token = strtok(NULL, whitespaces);
	if (port_token == NULL)
	{
		printf("No token\n");
		return -1;
	}
	pthread_mutex_lock(&errno_mutex);
	errno = 0;
	int port_number = (int) strtol(port_token, NULL, 0);
	if (errno)
	{
		printf("error %d:%s\n", errno, strerror(errno));
		return -1;	
	}
	pthread_mutex_unlock(&errno_mutex);
	return port_number;
}
void printhelp(char* str)
{
	char help_command[MAX_COMMAND_LEN] = "";
		char *helptoken = strtok(NULL, whitespaces);
	if (helptoken != NULL)
	{
		strncpy(help_command, helptoken, MAX_COMMAND_LEN-1);
		help_command[MAX_COMMAND_LEN-1] = '\0';
	}
	else
	{
		help_command[0] = '\0';
	}	
	if (strcmp(help_command,"quit") == 0)
	{
		printf("quit will exit vchat\nquit takes no arguments\n\n");
		return;
	}
	if (strcmp(help_command, "") == 0)
	{
		;
	}
	else
	{
		printf("There is no help page for %s.\n", help_command);
	}
	printf("Available commands:\n");
	printf(" help  - Show this message\n");
	printf(" quit  - Exit vchat\n");

}
int initialize_socket()
{
	int new_socket;
	errno = 0;
	if ((new_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("socket %d:%s", errno, strerror(errno));
		close(new_socket);
		exit(EXIT_FAILURE);
	}
	return new_socket;
}
void bind_socket(int socket, int port)
{
	struct sockaddr_in address;
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = htons(port);
	
	if (bind(socket, (struct sockaddr *) &address, sizeof(address)) < 0)
	{
		printf("bind %d:%s", errno, strerror(errno));
		close(socket);
		exit(EXIT_FAILURE);
	}
}
void *run_server(void *port_pointer)
{
	int port = (int)(intptr_t)port_pointer;
	int server_socket = initialize_socket();
	printf("%d\n", port);
	bind_socket(server_socket,port);
	
	struct sockaddr_in server_socket_address;
	int address_size = sizeof(server_socket_address);
	if (getsockname(server_socket, (struct sockaddr *)&server_socket_address, &address_size) < 0)
	{
		printf("getsockname\n");
		close(server_socket);
		exit(EXIT_FAILURE);
	}
	char server_ip_string[16];
	if (inet_ntop(AF_INET, &server_socket_address.sin_addr, server_ip_string, INET_ADDRSTRLEN) == NULL)
	{
		printf("inet_ntop");
		close(server_socket);
		exit(EXIT_FAILURE);
	}
	printf("Successfully created socket: %s:%d\n", server_ip_string, ntohs(server_socket_address.sin_port));
	listen(server_socket,5);
	while (1)
	{
		struct sockaddr_in client_address;
		int connection;
		int client_address_size = sizeof(client_address);
		pthread_t connection_tid;
		if ( (connection = accept(server_socket, (struct sockaddr *) &client_address, &client_address_size)) > 0 )
		{
			if (pthread_create(&connection_tid, NULL, handle_client, (void *) &connection) < 0)
			{
				printf("pthread_create");
				close(server_socket);
				close(connection);
				exit(EXIT_FAILURE);
			}
			pthread_detach(connection_tid);
		}
		sleep(1);
	}
	return NULL;
}

void *handle_client(void *client)
	// client should be an integer
{
	printf("I am here\n");
	int connection_socket = *((int *) client);
	struct sockaddr_in client_socket_address;
	int address_size = sizeof(client_socket_address);
	char client_ip_string[16];
	pthread_mutex_lock(&errno_mutex);
	errno = 0;
	if (getpeername(connection_socket, (struct sockaddr *)&client_socket_address, &address_size) < 0)
	{
		printf("getpeername %d:%s", errno, strerror(errno));
		pthread_mutex_unlock(&errno_mutex);
		close(connection_socket);
		return NULL;
	}
	pthread_mutex_unlock(&errno_mutex);
	if (inet_ntop(AF_INET, &client_socket_address.sin_addr, client_ip_string, INET_ADDRSTRLEN) == NULL)
	{
		printf("inet_ntop");
		close(connection_socket);
		return NULL;
	}

	printf("Connected to client %s:%d\n", client_ip_string, ntohs(client_socket_address.sin_port));
	char message_buffer[MAX_MESSAGE_SIZE];
	int bytes_read;
	for (;;)
	{
		if ( (bytes_read = read(connection_socket, &message_buffer, MAX_MESSAGE_SIZE)) > 0 ) 
		{
			printf("Received message from %s:%d: %s\n",client_ip_string,ntohs(client_socket_address.sin_port),message_buffer);
		}
		sleep(1);
	}
	return NULL;
}
void *send_message(void *server_address_ptr, void *message_string)
{
	int client_socket; int server_socket;
	struct sockaddr *server_address = (struct sockaddr *)server_address_ptr;
	struct sockaddr_in server_socketaddress = *(struct sockaddr_in *)server_address_ptr;
	char ip_string[16];
	if (inet_ntop(AF_INET, &server_socketaddress.sin_addr, ip_string, INET_ADDRSTRLEN) == NULL)
	{
		printf("inet_ntop");
		return NULL;
	}
	printf("Connecting to client %s:%d\n", ip_string, ntohs(server_socketaddress.sin_port));
	

	client_socket = initialize_socket();
	errno = 0;
	int attempts = 0;
	pthread_mutex_lock(&errno_mutex);
	while ( (connect(client_socket, (struct sockaddr *)&server_socketaddress, sizeof(server_socketaddress))) < 0)
	{
		attempts++;
		if (errno == 111)
		{
			printf("Errno %d:%s", errno, strerror(errno));
			close(client_socket);
			exit(EXIT_FAILURE);
		}
		if (attempts < 5)
		{
			printf("Client socket failed to connect, retrying...\n");
		}
		else
		{
			printf("Failed to connect. %d:%s\n", errno, strerror(errno));
			return NULL;
		}
		pthread_mutex_unlock(&errno_mutex);
		sleep(1);
		pthread_mutex_lock(&errno_mutex);
	}
	pthread_mutex_unlock(&errno_mutex);

	char message[MAX_MESSAGE_SIZE];
	strncpy(message, (char *)message_string, MAX_MESSAGE_SIZE);
	int bytes_sent;

	if ((bytes_sent = write(client_socket, &message, MAX_MESSAGE_SIZE)) < 0)
	{
		printf("write error %d:%s\n", errno, strerror(errno));
		close(client_socket);
		return NULL;
	}
	printf("Sent message\n");
	return NULL;
}
