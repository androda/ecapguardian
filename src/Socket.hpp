// Socket class - implements BaseSocket for INET domain sockets

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_SOCKET
#define __HPP_SOCKET

// INCLUDES

#include "BaseSocket.hpp"

// DECLARATIONS

class Socket : public BaseSocket
{
    friend class FDTunnel;
public:
    // create INET socket & clear address structs
    Socket();
    // create socket using pre-existing FD (address structs will be empty!)
    Socket(int fd);
    // create socket from pre-existing FD, storing given local & remote IPs
    Socket(int newfd, struct sockaddr_in myip, struct sockaddr_in peerip);

    // connect to given IP & port (following default constructor)
    int connect(const std::string& ip, int port);

    // bind to given port
    int bind(int port);
    // bind to given IP & port, for machines with multiple NICs
    int bind(const std::string& ip, int port);

    // accept incoming connections & return new Socket
    Socket* accept();

    // close socket & clear address structs
    void reset();

    // get remote IP/port
    std::string getPeerIP();
    int getPeerSourcePort();
    int getPort();
    void setPort(int port);
    unsigned long int getPeerSourceAddr();

    // get local IP
    std::string getLocalIP();
    int getLocalPort();

private:
    // local & remote addresses
    struct sockaddr_in my_adr;
    struct sockaddr_in peer_adr;
    int my_port;
};

#endif

