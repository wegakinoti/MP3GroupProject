/******************************************************************************

PROGRAM:  server.c
AUTHOR:   Tristan Chavez, Nhi La, Wega Kinoti
COURSE:   CS469 - Distributed Systems (Regis University)
SYNOPSIS: 

To build the program, you must install both the libsdl2-dev library
/           as well as the SDL2_mixer library:
/
/           sudo apt-get install -y libsdl2-dev libsdl2-mixer-2.0-0 libsdl2-mixer-dev
/
/           Then compile it and link with both the -lSDL2_mixer and -lSDL2
/           DSOs:
/
/           gcc -o playaudio playaudio.c `sdl2-config --cflags --libs`
/           -lSDL2_mixer
/
/           Note the installation of the SDL2 Mixer library has a dash, but linking
/           the DSO uses an underscore
/
/           The sdl2-config part is enclosed in backticks, not single quotes

******************************************************************************/
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <SDL2/SDL.h>
#include <SDL2/SDL_mixer.h>


#define BUFFER_SIZE       256
#define DEFAULT_PORT      4433
#define CERTIFICATE_FILE  "cert.pem"
#define KEY_FILE          "key.pem"

/******************************************************************************

This function does the basic necessary housekeeping to establish TCP connections
to the server.  It first creates a new socket, binds the network interface of the 
machine to that socket, then listens on the socket for incoming TCP connections.

*******************************************************************************/
int create_socket(unsigned int port)
{
    int    s;
    struct sockaddr_in addr;

    // First we set up a network socket. An IP socket address is a combination
    // of an IP interface address plus a 16-bit port number. The struct field
    // sin_family is *always* set to AF_INET. Anything else returns an error.
    // The TCP port is stored in sin_port, but needs to be converted to the
    // format on the host machine to network byte order, which is why htons()
    // is called. Setting s_addr to INADDR_ANY binds the socket and listen on
    // any available network interface on the machine, so clients can connect
    // through any, e.g., external network interface, localhost, etc.

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Create a socket (endpoint) for network communication.  The socket()
    // call returns a socket descriptor, which works exactly like a file
    // descriptor for file system operations we worked with in CS431
    //
    // Sockets are by default blocking, so the server will block while reading
    // from or writing to a socket. For most applications this is acceptable.
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
      {
	fprintf(stderr, "Server: Unable to create socket: %s", strerror(errno));
	exit(EXIT_FAILURE);
      }

    // When you create a socket, it exists within a namespace, but does not have
    // a network address associated with it.  The bind system call creates the
    // association between the socket and the network interface.
    //
    // An error could result from an invalid socket descriptor, an address already
    // in use, or an invalid network address
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0)
      {
	fprintf(stderr, "Server: Unable to bind to socket: %s", strerror(errno));
	exit(EXIT_FAILURE);
      }

    // Listen for incoming TCP connections using the newly created and configured
    // socket. The second argument (1) indicates the number of pending connections
    // allowed, which in this case is one.  That means if the server is connected
    // to one client, a second client attempting to connect may receive an error,
    // e.g., connection refused.
    //
    // Failure could result from an invalid socket descriptor or from using a socket
    // descriptor that is already in use.
    if (listen(s, 1) < 0)
      {
	fprintf(stderr, "Server: Unable to listen: %s", strerror(errno));
	exit(EXIT_FAILURE);
      }

    fprintf(stdout, "Server: Listening on TCP port %u\n", port);

    return s;
}

/******************************************************************************

This function does some initialization of the OpenSSL library functions used in 
this program.  The function SSL_load_error_strings registers the error strings 
for all of the libssl and libcrypto functions so that appropriate textual error 
messages can be displayed when error conditions arise.  OpenSSL_add_ssl_algorithms 
registers the available SSL/TLS ciphers and digests used for encryption.

******************************************************************************/
void init_openssl()
{ 
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();
}

/******************************************************************************

EVP_cleanup removes all of the SSL/TLS ciphers and digests registered earlier.

******************************************************************************/
void cleanup_openssl()
{
    EVP_cleanup();
}

/******************************************************************************

An SSL_CTX object is an instance of a factory design pattern that produces SSL
connection objects, each called a context. A context is used to set parameters 
for the connection, and in this program, each context is configured using the 
configure_context() function below. Each context object is created using the 
function SSL_CTX_new(), and the result of that call is what is returned by this 
function and subsequently configured with connection information.

One other thing to point out is when creating a context, the SSL protocol must
be specified ahead of time using an instance of an SSL_method object.  In this
case, we are creating an instance of an SSLv23_server_method, which is an
SSL_METHOD object for an SSL/TLS server. Of the available types in the OpenSSL
library, this provides the most functionality.

******************************************************************************/
SSL_CTX* create_new_context()
{
  const SSL_METHOD* ssl_method; // This should be declared 'const' to avoid getting
                                // a warning from the call to SSLv23_server_method()
        SSL_CTX*    ssl_ctx;

    // Use SSL/TLS method for server
    ssl_method = SSLv23_server_method();

    // Create new context instance
    ssl_ctx = SSL_CTX_new(ssl_method);
    if (ssl_ctx == NULL)
      {
	fprintf(stderr, "Server: cannot create SSL context:\n");
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
      }

    return ssl_ctx;
}

/******************************************************************************

We will use Elliptic Curve Diffie Hellman anonymous key agreement protocol for
the session key shared between client and server.  We first configure the SSL 
context to use that protocol by calling the function SSL_CTX_set_ecdh_auto(). 
The second argument (onoff) tells the function to automatically use the highest
preference curve (supported by both client and server) for the key agreement.

Note that for error conditions specific to SSL/TLS, the OpenSSL library does
not set the variable errno, so we must use the built-in error printing routines.

******************************************************************************/
void configure_context(SSL_CTX* ssl_ctx)
{
    SSL_CTX_set_ecdh_auto(ssl_ctx, 1);

    // Set the certificate to use, i.e., 'cert.pem' 
    if (SSL_CTX_use_certificate_file(ssl_ctx, CERTIFICATE_FILE, SSL_FILETYPE_PEM) <= 0)
      {
	fprintf(stderr, "Server: cannot set certificate:\n");
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
      }

    // Set the private key contained in the key file, i.e., 'key.pem'
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0 )
      {
	fprintf(stderr, "Server: cannot set certificate:\n");
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
      }
}

int main(int argc, char **argv)
{
    SSL_CTX*     ssl_ctx;
    unsigned int sockfd;
    unsigned int port;
    char         buffer[BUFFER_SIZE];
    
    char buffer[128];             // Used to read the entire 128-byte ID3 tag
    char title[31];               // 30-byte title field from the ID3 tag
    char artist[31];              // 30-byte artist field from the ID3 tag
    char album[31];               // 30-byte album field from the ID3 tag
    char year[5];                 // 4-byte year field from the ID3 tag
    int  flags  = MIX_INIT_MP3;   // Mix_Init initializer flags for MP3 files
    int  result;
    int  fd;

    // Initialize and create SSL data structures and algorithms
    init_openssl();
    ssl_ctx = create_new_context();
    configure_context(ssl_ctx);

    // Port can be specified on the command line. If it's not, use the default port 
    switch(argc)
      {
        case 1:
	  port = DEFAULT_PORT;
	  break;
        case 2:
  	  port = atoi(argv[1]);
	  break;
        default:
	  fprintf(stderr, "Usage: ssl-server <port> (optional)\n");
	  exit(EXIT_FAILURE);
      }

    // This will create a network socket and return a socket descriptor, which is
    // and works just like a file descriptor, but for network communcations. Note
    // we have to specify which TCP/UDP port on which we are communicating as an
    // argument to our user-defined create_socket() function.
    sockfd = create_socket(port);

    // Wait for incoming connections and handle them as the arrive
    while(true)
      {
        SSL*               ssl;
	int                client;
	int                readfd;
	int                rcount;
        const  char        reply[] = "Hello World!";
        struct sockaddr_in addr;
        unsigned int       len = sizeof(addr);
	char               client_addr[INET_ADDRSTRLEN];
	
	// Once an incoming connection arrives, accept it.  If this is successful, we
	// now have a connection between client and server and can communicate using
	// the socket descriptor
        client = accept(sockfd, (struct sockaddr*)&addr, &len);
        if (client < 0)
	  {
            fprintf(stderr, "Server: Unable to accept connection: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
	  }

	// Display the IPv4 network address of the connected client
	inet_ntop(AF_INET, (struct in_addr*)&addr.sin_addr, client_addr, INET_ADDRSTRLEN);
	fprintf(stdout, "Server: Established TCP connection with client (%s) on port %u\n", client_addr, port);
	
	// Here we are creating a new SSL object to bind to the socket descriptor
        ssl = SSL_new(ssl_ctx);

	// Bind the SSL object to the network socket descriptor.  The socket descriptor
	// will be used by OpenSSL to communicate with a client. This function should
	// only be called once the TCP connection is established.
        SSL_set_fd(ssl, client);

	// The last step in establishing a secure connection is calling SSL_accept(),
	// which executes the SSL/TLS handshake.  Because network sockets are
	// blocking by default, this function will block as well until the handshake
	// is complete.
        if (SSL_accept(ssl) <= 0)
	  {
	    fprintf(stderr, "Server: Could not establish secure connection:\n");
            ERR_print_errors_fp(stderr);
          }
        else
	  fprintf(stdout, "Server: Established SSL/TLS connection with client (%s)\n", client_addr);

	// ************************************************************************
	// Play Audio Code Here
	// ************************************************************************
         
          if (argc != 2) {
             fprintf(stderr, "Usage: playaudio <mp3 file name>\n");
             return EXIT_FAILURE;
           }

           // Open the MP3 file to get the metadata from the ID3 tag
           fd = open(argv[1], O_RDONLY);
           if (fd < 0) {
             fprintf(stderr, "Could not open %s: %s\n", argv[1], strerror(errno));
             return EXIT_FAILURE;
           }

           // MP3 metadata (ID3v1 format) is the last 128 bytes of the file. Note that
           // ID3v2 uses the first 128 bytes.  Reposition 128 bytes from the end of
           // the file so we can read the ID3 tag.
           lseek(fd, -128L, SEEK_END);

           // Read the 128-byte ID3 tag from the end of the file
           read(fd, buffer, 128);
           close(fd);

           // First 3 bytes are "ID3". Next 30 bytes after that are the song title
           strncpy(title, buffer+3, 30);
           // Next 30 bytes after title are the artist name
           strncpy(artist, buffer+33, 30);
           // Next 30 bytes after artist are the album name
           strncpy(album, buffer+63, 30);
           // After the album name is the year the album was released
           strncpy(year, buffer+93, 4);

           printf("Now Playing:\n  Title: %s\n", title);
           printf("  Artist: %s\n", artist);
           printf("  Album: %s\n", album);
           printf("  Year: %s\n", year);

           // Initialize the SDL2 Mixer and check for error
           result = Mix_Init(flags);
           if (flags != result) {
             fprintf(stderr, "Could not initialize mixer (result: %d).\n", result);
             fprintf(stderr, "playaudio: %s\n", Mix_GetError());
             return EXIT_FAILURE;
           }

           // Open the MP3 file. 44.1kHz represents the sample rate, 2 = stereo,
           // and 1024 means the file will be processed in 1 KB chunks.
           if (Mix_OpenAudio(44100, AUDIO_S16SYS, 2, 1024) < 0) {
             fprintf(stderr, "playaudio: %s\n", Mix_GetError());
             return EXIT_FAILURE;
           }

           // Loads the music file given on the command line
           Mix_Music *music = Mix_LoadMUS(argv[1]);
           if(!music) {
             fprintf(stderr, "playaudio: %s\n", Mix_GetError());
             return EXIT_FAILURE;
           }

           // Play the music! The second parameter sets the number of times to play
           // the song. A value of -1 is used for looping.
           Mix_PlayMusic(music, 1);

           // This needs to be here otherwise the program terminates immediately.
           // Delay value doesn't seem to matter much. Once the music stops playing,
           // program exits the loop and terminates.
           while (1) {
             SDL_Delay(200);
             if (Mix_PlayingMusic() == 0)
               break;
           }

           // Clean up dynamically allocated memory
           Mix_FreeMusic(music);
           Mix_CloseAudio();
           Mix_Quit();
          
          
          
	
        // File transfer complete
	fprintf(stdout, "Server: Completed file transfer to client (%s)\n", client_addr);
	    
	// Terminate the SSL session, close the TCP connection, and clean up
	fprintf(stdout, "Server: Terminating SSL session and TCP connection with client (%s)\n", client_addr);
        SSL_free(ssl);
        close(client);
    }

    // Tear down and clean up server data structures before terminating
    SSL_CTX_free(ssl_ctx);
    cleanup_openssl();
    close(sockfd);

    return 0;
}
