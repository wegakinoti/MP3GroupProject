/******************************************************************************

PROGRAM:  client.c
AUTHOR:   Tristan Chavez, Nhi La, Wega Kinoti
COURSE:   CS469 - Distributed Systems (Regis University)
SYNOPSIS: 

******************************************************************************/
#include <netdb.h>
#include <errno.h>
#include <resolv.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <time.h>
#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>

#define DEFAULT_PORT        4433
#define DEFAULT_HOST        "localhost"
#define MAX_HOSTNAME_LENGTH 256
#define BUFFER_SIZE         256
#define PASSWORD_LENGTH     32
#define SEED_LENGTH         8

/******************************************************************************

This function does the basic necessary housekeeping to establish a secure TCP
connection to the server specified by 'hostname'.

*******************************************************************************/
int create_socket(char* hostname, unsigned int port)
{
  int                sockfd;
  struct hostent*    host;
  struct sockaddr_in dest_addr;

  host = gethostbyname(hostname);
  if (host == NULL)
    {
      fprintf(stderr, "Client: Cannot resolve hostname %s\n",  hostname);
      exit(EXIT_FAILURE);
    }
  
  // Create a socket (endpoint) for network communication.  The socket()
  // call returns a socket descriptor, which works exactly like a file
  // descriptor for file system operations we worked with in CS431
  //
  // Sockets are by default blocking, so the server will block while reading
  // from or writing to a socket. For most applications this is acceptable.
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    {
      fprintf(stderr, "Server: Unable to create socket: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
  
  // First we set up a network socket. An IP socket address is a combination
  // of an IP interface address plus a 16-bit port number. The struct field
  // sin_family is *always* set to AF_INET. Anything else returns an error.
  // The TCP port is stored in sin_port, but needs to be converted to the
  // format on the host machine to network byte order, which is why htons()
  // is called. The s_addr field is the network address of the remote host
  // specified on the command line. The earlier call to gethostbyname()
  // retrieves the IP address for the given hostname.
  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
  dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);
  
  // Now we connect to the remote host.  We pass the connect() system call the
  // socket descriptor, the address of the remote host, and the size in bytes
  // of the remote host's address
  if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) <0)
    {
      fprintf(stderr, "Client: Cannot connect to host %s [%s] on port %d: %s\n",
	      hostname, inet_ntoa(dest_addr.sin_addr), port, strerror(errno));
      exit(EXIT_FAILURE);
    }

  return sockfd;
}

void getPassword(char* password) {
    static struct termios oldsettings, newsettings;
    int c, i = 0;

    // Save the current terminal settings and copy settings for resetting
    tcgetattr(STDIN_FILENO, &oldsettings);
    newsettings = oldsettings;

    // Hide, i.e., turn off echoing, the characters typed to the console
    newsettings.c_lflag &= ~(ECHO);

    // Set the new terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &newsettings);

    // Read the password from the console one character at a time
    while ((c = getchar())!= '\n' && c != EOF && i < BUFFER_SIZE)
      password[i++] = c;

    password[i] = '\0';

    // Restore the old (saved) terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldsettings);
}

int main(int argc, char** argv)
{
  const SSL_METHOD* method;
  unsigned int      port = DEFAULT_PORT;
  char              remote_host[MAX_HOSTNAME_LENGTH];
  char              buffer[BUFFER_SIZE];
  char*             temp_ptr;
  char	            response[BUFFER_SIZE];
  char	            password[PASSWORD_LENGTH];
  char	            username[BUFFER_SIZE];
  int               sockfd;
  int               writefd;
  int               rcount;
  int               wcount;
  int               total = 0;
  SSL_CTX*          ssl_ctx;
  SSL*              ssl;
  
  if (argc != 2)
    {
      fprintf(stderr, "Client: Usage: ssl-client <server name>:<port>\n");
      exit(EXIT_FAILURE);
    }
  else
    {
      // Search for ':' in the argument to see if port is specified
      temp_ptr = strchr(argv[1], ':');
      if (temp_ptr == NULL)    // Hostname only. Use default port
	  strncpy(remote_host, argv[1], MAX_HOSTNAME_LENGTH);
      else
	{
	  // Argument is formatted as <hostname>:<port>. Need to separate
	  // First, split out the hostname from port, delineated with a colon
	  // remote_host will have the <hostname> substring
	  strncpy(remote_host, strtok(argv[1], ":"), MAX_HOSTNAME_LENGTH);
	  // Port number will be the substring after the ':'. At this point
	  // temp is a pointer to the array element containing the ':'
	  port = (unsigned int) atoi(temp_ptr+sizeof(char));
	}
    }
  
  // Initialize OpenSSL ciphers and digests
  OpenSSL_add_all_algorithms();

  // SSL_library_init() registers the available SSL/TLS ciphers and digests.
  if(SSL_library_init() < 0)
    {
      fprintf(stderr, "Client: Could not initialize the OpenSSL library!\n");
      exit(EXIT_FAILURE);
    }

  // Use the SSL/TLS method for clients
  method = SSLv23_client_method();

  // Create new context instance
  ssl_ctx = SSL_CTX_new(method);
  if (ssl_ctx == NULL)
    {
      fprintf(stderr, "Unable to create a new SSL context structure.\n");
      exit(EXIT_FAILURE);
    }

  // This disables SSLv2, which means only SSLv3 and TLSv1 are available
  // to be negotiated between client and server
  SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);

  // Create a new SSL connection state object                     
  ssl = SSL_new(ssl_ctx);

  // Create the underlying TCP socket connection to the remote host
  sockfd = create_socket(remote_host, port);
  if(sockfd != 0)
    fprintf(stderr, "Client: Established TCP connection to '%s' on port %u\n", remote_host, port);
  else
    {
      fprintf(stderr, "Client: Could not establish TCP connection to %s on port %u\n", remote_host, port);
      exit(EXIT_FAILURE);
    }

  // Bind the SSL object to the network socket descriptor.  The socket descriptor
  // will be used by OpenSSL to communicate with a server. This function should only
  // be called once the TCP connection is established, i.e., after create_socket()
  SSL_set_fd(ssl, sockfd);

  // Initiates an SSL session over the existing socket connection.  SSL_connect()
  // will return 1 if successful.
  if (SSL_connect(ssl) == 1)
    fprintf(stdout, "Client: Established SSL/TLS session to '%s' on port %u\n", remote_host, port);
  else
    {
      fprintf(stderr, "Client: Could not establish SSL session to '%s' on port %u\n", remote_host, port);
      exit(EXIT_FAILURE);
    }
  
  fprintf(stdout, "Please indicate if you want to SIGNIN, CREATE an account or CANCEL\n");
  fgets(response, BUFFER_SIZE-1, stdin);
  fprintf(stdout, "%s", response);
  while(strncmp(response, "CANCEL", 6) != 0) {
    if (strncmp(response, "SIGNIN", 6) == 0) {
      fprintf(stdout, "Please enter your username\n");
      
    }
    else if (strncmp(response, "CREATE", 6) == 0) {
      fprintf(stdout, "Please enter your new username\n");
    }
    else {
      fprintf(stdout, "Unknown input, please type in SIGNIN, CREATE an account or CANCEL\n");
      fgets(response, BUFFER_SIZE-1, stdin);
    }
  }

  // Deallocate memory for the SSL data structures and close the socket
  SSL_free(ssl);
  SSL_CTX_free(ssl_ctx);
  close(sockfd);
  fprintf(stdout, "Client: Terminated SSL/TLS connection with server '%s'\n", remote_host);
  
  return(0);
}
