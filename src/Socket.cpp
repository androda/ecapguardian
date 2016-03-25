// Socket class - implements BaseSocket for INET domain sockets

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.


// INCLUDES
#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif
#include "Socket.hpp"

#include <string.h>
#include <syslog.h>
#include <csignal>
#include <fcntl.h>
#include <sys/time.h>
#include <pwd.h>
#include <stdexcept>
#include <cerrno>
#include <unistd.h>
#include <netinet/tcp.h>

// IMPLEMENTATION

// constructor - create an INET socket & clear address structs
Socket::Socket()
{
    sck = socket(AF_INET, SOCK_STREAM, 0);

    memset(&my_adr, 0, sizeof my_adr);
    memset(&peer_adr, 0, sizeof peer_adr);
    my_adr.sin_family = AF_INET;
    peer_adr.sin_family = AF_INET;
    peer_adr_length = sizeof(struct sockaddr_in);
    int f = 1;

    if (sck > 0)
        int res = setsockopt(sck, IPPROTO_TCP, TCP_NODELAY, &f, sizeof(int));

    my_port = 0;
}

// create socket from pre-existing FD (address structs will be invalid!)
Socket::Socket(int fd):BaseSocket(fd)
{
    memset(&my_adr, 0, sizeof my_adr);
    memset(&peer_adr, 0, sizeof peer_adr);
    my_adr.sin_family = AF_INET;
    peer_adr.sin_family = AF_INET;
    peer_adr_length = sizeof(struct sockaddr_in);
    int f = 1;

    int res = setsockopt(sck, IPPROTO_TCP, TCP_NODELAY, &f, sizeof(int));

    my_port = 0;
}

// create socket from pre-existing FD, storing local & remote IPs
Socket::Socket(int newfd, struct sockaddr_in myip, struct sockaddr_in peerip):BaseSocket(newfd)
{
    memset(&my_adr, 0, sizeof my_adr);  // ***
    memset(&peer_adr, 0, sizeof peer_adr);  // ***
    my_adr.sin_family = AF_INET;  // *** Fix suggested by
    peer_adr.sin_family = AF_INET;  // *** Christopher Weimann
    my_adr = myip;
    peer_adr = peerip;
    peer_adr_length = sizeof(struct sockaddr_in);
    int f = 1;

    int res = setsockopt(sck, IPPROTO_TCP, TCP_NODELAY, &f, sizeof(int));

    my_port = 0;
}

// find the ip to which the client has connected
std::string Socket::getLocalIP()
{
    return inet_ntoa(my_adr.sin_addr);
}

// find the ip of the client connecting to us
std::string Socket::getPeerIP()
{
    return inet_ntoa(peer_adr.sin_addr);
}

// find the port of the client connecting to us
int Socket::getPeerSourcePort()
{
    return ntohs(peer_adr.sin_port);
}
int Socket::getPort()
{
    return my_port;
}
void Socket::setPort(int port)
{
    my_port = port;
}

// return the address of the client connecting to us
unsigned long int Socket::getPeerSourceAddr()
{
    return (unsigned long int)ntohl(peer_adr.sin_addr.s_addr);
}

// close connection & wipe address structs
void Socket::reset()
{
    this->baseReset();

    sck = socket(AF_INET, SOCK_STREAM, 0);

    memset(&my_adr, 0, sizeof my_adr);
    memset(&peer_adr, 0, sizeof peer_adr);
    my_adr.sin_family = AF_INET;
    peer_adr.sin_family = AF_INET;
    peer_adr_length = sizeof(struct sockaddr_in);
}

// connect to given IP & port (following default constructor)
int Socket::connect(const std::string &ip, int port)
{
    int len = sizeof my_adr;
    peer_adr.sin_port = htons(port);
    inet_aton(ip.c_str(), &peer_adr.sin_addr);
    my_port = port;

    return ::connect(sck, (struct sockaddr *) &peer_adr, len);
}
// bind socket to given port
int Socket::bind(int port)
{
    int len = sizeof my_adr;
    int i = 1;

    int res = setsockopt(sck, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));

    my_adr.sin_port = htons(port);
    my_port = port;

    return ::bind(sck, (struct sockaddr *) &my_adr, len);
}

// bind socket to given port & IP
int Socket::bind(const std::string &ip, int port)
{
    int len = sizeof my_adr;
    int i = 1;

    int res = setsockopt(sck, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));

    my_adr.sin_port = htons(port);
    my_adr.sin_addr.s_addr = inet_addr(ip.c_str());
    my_port = port;

    return ::bind(sck, (struct sockaddr *) &my_adr, len);
}

// accept incoming connections & return new Socket
Socket* Socket::accept()
{
    peer_adr_length = sizeof(struct sockaddr_in);
    int newfd = this->baseAccept((struct sockaddr*) &peer_adr, &peer_adr_length);

    if (newfd > 0)    {
        Socket* s = new Socket(newfd, my_adr, peer_adr);
        s->setPort(my_port);
        return s;
    }
    else
        return NULL;
}
