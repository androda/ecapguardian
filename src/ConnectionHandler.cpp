// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.


// INCLUDES
#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif
#include "ConnectionHandler.hpp"
#include "DataBuffer.hpp"
#include "UDSocket.hpp"
#include "BaseSocket.hpp"
#include "Auth.hpp"
#include "FDTunnel.hpp"
#include "BackedStore.hpp"
#include "ImageContainer.hpp"
#include "FDFuncs.hpp"
#include <signal.h>

#include <syslog.h>
#include <cerrno>
#include <cstdio>
#include <stdio.h>
#include <ctime>
#include <algorithm>
#include <netdb.h>
#include <cstdlib>
#include <unistd.h>
#include <sys/time.h>
#include <strings.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <istream>
#include <sstream>
#include <memory>

#ifdef ENABLE_ORIG_IP
#include <linux/types.h>
#include <linux/netfilter_ipv4.h>
#endif

// GLOBALS
extern OptionContainer o;
extern bool is_daemonised;
extern bool reloadconfig;

const std::string blockHeaders("HTTP/1.1 200 OK\nAccept-Ranges: bytes\nConnection: close\nContent-Type: text/html; charset=UTF-8\n\n\0\0");
const char FLAG_USE_VIRGIN = 'v';
const char FLAG_MODIFY = 'm';
const char FLAG_BLOCK = 'b';
const char FLAG_NEEDS_SCAN = 's';
const char FLAG_MSG_RECVD = 'r';
const std::string FLAG_END = "\n\n\0\0";

#ifdef DGDEBUG
int dbgPeerPort;
#endif

// IMPLEMENTATION

// Custom exception class for POST filtering errors
class postfilter_exception: public std::runtime_error
{
public:
    postfilter_exception(const char *const &msg)
            : std::runtime_error(msg)
    {};
};

//
// URL cache funcs
//

// check the URL cache to see if we've already flagged an address as clean
bool wasClean(HTTPHeader &header, String &url, const int fg)
{
    if (reloadconfig)
        return false;
    if ((header.requestType() != "GET") || url.length() > 2000)
        return false; // only check GET and normal length urls
    UDSocket ipcsock;
    if (ipcsock.getFD() < 0)    {
        syslog(LOG_ERR, "Error creating ipc socket to url cache");
        return false;
    }
    if (ipcsock.connect(o.urlipc_filename.c_str()) < 0)  	// conn to dedicated url cach proc
    {
        syslog(LOG_ERR, "Error connecting via ipc to url cache: %s", strerror(errno));
        ipcsock.close();
        return false;
    }
    std::string myurl(" ");
    myurl += url.after("://").toCharArray();
    myurl[0] = fg+1;
    myurl += "\n";
#ifdef DGDEBUG
    std::cout << dbgPeerPort << " -sending cache search request: " << myurl;
#endif
    try    {
        ipcsock.writeString(myurl.c_str());  // throws on err
    }
    catch (std::exception & e)    {
#ifdef DGDEBUG
        std::cerr << dbgPeerPort << " -Exception writing to url cache" << std::endl;
        std::cerr << e.what() << std::endl;
#endif
        syslog(LOG_ERR, "Exception writing to url cache");
        syslog(LOG_ERR, "%s", e.what());
    }
    char reply;
    try    {
        ipcsock.readFromSocket(&reply, 1, 0, 6);  // throws on err
    }
    catch (std::exception & e)    {
#ifdef DGDEBUG
        std::cerr << dbgPeerPort << " -Exception reading from url cache" << std::endl;
        std::cerr << e.what() << std::endl;
#endif
        syslog(LOG_ERR, "Exception reading from url cache");
        syslog(LOG_ERR, "%s", e.what());
    }
    ipcsock.close();
    return reply == 'Y';
}

// add a known clean URL to the cache
void addToClean(String &url, const int fg)
{
    if (reloadconfig)
        return;
    UDSocket ipcsock;
    if (ipcsock.getFD() < 0)    {
        syslog(LOG_ERR, "Error creating ipc socket to url cache");
        return;
    }
    if (ipcsock.connect(o.urlipc_filename.c_str()) < 0)  	// conn to dedicated url cach proc
    {
        syslog(LOG_ERR, "Error connecting via ipc to url cache: %s", strerror(errno));
#ifdef DGDEBUG
        std::cout << dbgPeerPort << " -Error connecting via ipc to url cache: " << strerror(errno) << std::endl;
#endif
        return;
    }
    std::string myurl("g ");
    myurl += url.after("://").toCharArray();
    myurl[1] = fg+1;
    myurl += "\n";
    try    {
        ipcsock.writeString(myurl.c_str());  // throws on err
    }
    catch (std::exception & e)    {
#ifdef DGDEBUG
        std::cerr << dbgPeerPort << " -Exception adding to url cache" << std::endl;
        std::cerr << e.what() << std::endl;
#endif
        syslog(LOG_ERR, "Exception adding to url cache");
        syslog(LOG_ERR, "%s", e.what());
    }
    ipcsock.close();
}

//
// ConnectionHandler class
//

// strip the URL down to just the IP/hostname, then do an isIPHostname on the result
bool ConnectionHandler::isIPHostnameStrip(String url)
{
    url = url.getHostname();
    return o.fg[0]->isIPHostname(url);
}

// perform URL encoding on a string
std::string ConnectionHandler::miniURLEncode(const char *s)
{
    std::string encoded;
    char *buf = new char[3];
    unsigned char c;
    for (int i = 0; i < (signed) strlen(s); i++)    {
        c = s[i];
        // allowed characters in a url that have non special meaning
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))        {
            encoded += c;
            continue;
        }
        // all other characters get encoded
        sprintf(buf, "%02x", c);
        encoded += "%";
        encoded += buf;
    }
    delete[]buf;
    return encoded;
}

// create a temporary bypass URL for the banned page
String ConnectionHandler::hashedURL(String *url, int filtergroup, std::string *clientip, bool infectionbypass)
{
    // filter/virus bypass hashes last for a certain time only
    String timecode(time(NULL) + (infectionbypass ? (*o.fg[filtergroup]).infection_bypass_mode : (*o.fg[filtergroup]).bypass_mode));
    // use the standard key in normal bypass mode, and the infection key in infection bypass mode
    String magic(infectionbypass ? o.fg[filtergroup]->imagic.c_str() : o.fg[filtergroup]->magic.c_str());
    magic += clientip->c_str();
    magic += timecode;
    String res(infectionbypass ? "GIBYPASS=" : "GBYPASS=");
    if (!url->after("://").contains("/"))    {
        String newurl((*url));
        newurl += "/";
        res += newurl.md5(magic.toCharArray());
    }    else    {
        res += url->md5(magic.toCharArray());
    }
    res += timecode;
    return res;
}

// create temporary bypass cookie
String ConnectionHandler::hashedCookie(String * url, const char *magic, std::string * clientip, int bypasstimestamp)
{
    String timecode(bypasstimestamp);
    String data(magic);
    data += clientip->c_str();
    data += timecode;
    String res(url->md5(data.toCharArray()));
    res += timecode;

#ifdef DGDEBUG
    std::cout << dbgPeerPort << " -hashedCookie=" << res << std::endl;
#endif
    return res;
}

// when using IP address counting - have we got any remaining free IPs?
bool ConnectionHandler::gotIPs(std::string ipstr){
    if (reloadconfig)
        return false;
    UDSocket ipcsock;
    if (ipcsock.getFD() < 0)    {
        syslog(LOG_ERR, "Error creating ipc socket to IP cache");
        return false;
    }
    // TODO: put in proper file name check
    if (ipcsock.connect(o.ipipc_filename.c_str()) < 0)    // connect to dedicated ip list proc
    {
        syslog(LOG_ERR, "Error connecting via ipc to IP cache: %s", strerror(errno));
        return false;
    }
    char reply;
    ipstr += '\n';
    try    {
        ipcsock.writeToSockete(ipstr.c_str(), ipstr.length(), 0, 6);
        ipcsock.readFromSocket(&reply, 1, 0, 6);  // throws on err
    }
    catch (std::exception& e)    {
#ifdef DGDEBUG
        std::cerr << dbgPeerPort << " -Exception with IP cache" << std::endl;
        std::cerr << e.what() << std::endl;
#endif
        syslog(LOG_ERR, "Exception with IP cache");
        syslog(LOG_ERR, "%s", e.what());
    }
    ipcsock.close();
    return reply == 'Y';
}

// send a file to the client - used during bypass of blocked downloads
off_t ConnectionHandler::sendFile(Socket * peerconn, String & filename, String & filemime, String & filedis, String &url)
{
    int fd = open(filename.toCharArray(), O_RDONLY);
    if (fd < 0)  		// file access error
    {
        syslog(LOG_ERR, "Error reading file to send");
#ifdef DGDEBUG
        std::cout << dbgPeerPort << " -Error reading file to send:" << filename << std::endl;
#endif
        String fnf(o.language_list.getTranslation(1230));
        String message("HTTP/1.0 404 " + fnf + "\nContent-Type: text/html\n\n<HTML><HEAD><TITLE>" + fnf + "</TITLE></HEAD><BODY><H1>" + fnf + "</H1></BODY></HTML>\n");
        peerconn->writeString(message.toCharArray());
        return 0;
    }

    off_t filesize = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    String message("HTTP/1.0 200 OK\nContent-Type: " + filemime + "\nContent-Length: " + String(filesize));
    if (filedis.length() == 0)    {
        filedis = url.before("?");
        while (filedis.contains("/"))
            filedis = filedis.after("/");
    }
    message += "\nContent-disposition: attachment; filename=" + filedis;
    message += "\n\n";
    try    {
        peerconn->writeString(message.toCharArray());
    }
    catch (std::exception & e)    {
        close(fd);
        return 0;
    }

    // perform the actual sending
    off_t sent = 0;
    int rc;
    char *buffer = new char[250000];
    while (sent < filesize)    {
        rc = readEINTR(fd, buffer, 250000);
#ifdef DGDEBUG
        std::cout << dbgPeerPort << " -reading send file rc:" << rc << std::endl;
#endif
        if (rc < 0)        {
#ifdef DGDEBUG
            std::cout << dbgPeerPort << " -error reading send file so throwing exception" << std::endl;
#endif
            delete[]buffer;
            throw std::runtime_error("::sendFile - error reading send file");
        }
        if (rc == 0)        {
#ifdef DGDEBUG
            std::cout << dbgPeerPort << " -got zero bytes reading send file" << std::endl;
#endif
            break;  // should never happen
        }
        // as it's cached to disk the buffer must be reasonably big
        if (!peerconn->writeToSocket(buffer, rc, 0, 100))        {
            delete[]buffer;
            throw std::runtime_error("::sendFile - could not write to peerconn");
        }
        sent += rc;
#ifdef DGDEBUG
        std::cout << dbgPeerPort << " -total sent from temp:" << sent << std::endl;
#endif
    }
    delete[]buffer;
    close(fd);
    return sent;
}

int ConnectionHandler::handleEcapReqmod(UDSocket &ecappeer){
    /*
    REQMOD: Grab the headers and scan/modify as necessary.
    If using the virgin headers, send 'v' to ecappeer.
    If modifying the headers, send 'm' to ecappeer, followed by a dump of the modified header.
    	-This does not check the request body
    */

    NaughtyFilter checkme;
    HTTPHeader requestHeader;
	//Set header read timeout - waiting forever is a bad thing
    requestHeader.setTimeout(o.pcon_timeout);

	///
	///Cleanup from previous REQMOD connections.  These variables are class-wide and declared in the header.
	///
    if(clienthost){
        delete clienthost;
    }
    clienthost = NULL;  // to hold the client hostname
    matchedip = false;  //no way we could have matched yet
    urlparams.clear();  // clear list of parameters extracted from URL
    postparts.clear();  // clear out info about POST data

    ///
    ///Setup for this REQMOD connection
    ///
    bool blockIt = false;
    bool urlModified = false;
    bool headerModified = false;
    std::string exceptionreason;  // to hold the reason for not blocking
    std::deque<CSPlugin*> requestscanners;  //the request scanners
    ScanFlags flags;  //The scanner flags
    char rBuf[1];
    int headersent = 0;  //Whether the header was sent. 0=none,1=first line,2=all
    int message_no = 0;
    int filtergroup = 0;  //Everyone is in the '0' filtergroup
    int gmode;
    int rc = 0;
    std::string mimetype("-");
    String url;
    String logurl;
    String urld;
    String urldomain;
    std::string appender("");
    std::string empty("");
    String emptyS(empty.c_str());

    const char FLAG_USE_VIRGIN = 'v';
#ifdef DGDEBUG
	std::cout << getpid() << "REQMOD filtergroup=" << filtergroup << std::endl;
#endif
    try{
        //The eCAP peer is going to just dump over the request header.  Therefore, read it in.
        requestHeader.in(&ecappeer, true, true);  // get header from eCAP client, allowing persistency and breaking on reloadconfig

        url = requestHeader.getUrl(false, false);  //No MITM here - Squid does that
        logurl = requestHeader.getLogUrl(false, false);  //No MITM here - Squid does that
        urld = requestHeader.decode(url);
        urldomain = url.getHostname();
/*#ifdef DGDEBUG
        std::cout << "requestType|url|logUrl|urld|urldomain: " << requestHeader.requestType() << '|'
            << url << '|' << logurl << '|' << urld << '|' << urldomain << std::endl;
#endif*/

        //A CONNECT request should either be ignored
        //OR check the destination and block if necessary
        if(requestHeader.requestType() == "CONNECT")
        {
            ecappeer.writeToSocket(&FLAG_USE_VIRGIN, 1, 0, 5, true, false);
            return 0;
        }

        // checks for bad URLs to prevent security holes/domain obfuscation.
        if (requestHeader.malformedURL(url))
        {
/*#ifdef DGDEBUG
            std::cout << "Malformed URL: " << url << std::endl;
#endif*/
            std::string badReq("400 Bad Request");
            std::string explan("Your browser made an invalid request, which cannot be fulfilled");
            //Block page signal
            ecappeer.writeToSocket(&FLAG_BLOCK, 1, 0, 0);
            //Blockpage headers
            ecappeer.writeToSocket(blockHeaders.c_str(), blockHeaders.length(), 0, 0);
            //Read back msg recvd signal
            rc = ecappeer.readFromSocket(rBuf, 1, 0, 10);
/*#ifdef DGDEBUG
            std::cout << "Received from adapter: " << rBuf[0] << std::endl;
#endif*/
            if(rBuf[0] == FLAG_MSG_RECVD){
                o.fg[filtergroup]->getHTMLTemplate()->display(&ecappeer, &url, badReq,
                    explan, empty, &empty, &empty, &empty, 0, emptyS);
            } else{
/*#ifdef DGDEBUG
                std::cout << "eCAP adapter did not return expected signal" << std::endl;
                std::cout << "Malformed URL, but did not receive 'r'. Recvd "
                    << rBuf[0] << std::endl;
#endif*/
            }
            //Success
            return 0;
        }

        //Modify the request URL (redirects to safe search stuff?)
        urlModified = requestHeader.urlRegExp(filtergroup);
        headerModified = requestHeader.headerRegExp(filtergroup);

// The new way to check requests
//    void ConnectionHandler::requestChecks(HTTPHeader *header, NaughtyFilter *checkme,
//        String *urld, String *url, int filtergroup)

        requestChecks(&requestHeader, &checkme, &urld, &url, 0);
        if(checkme.isItNaughty){
/*#ifdef DGDEBUG
            std::cout << "Was naughty, blocked: " << checkme.whatIsNaughty << '|'
                 << checkme.whatIsNaughtyCategories << std::endl;
#endif*/
            ecappeer.writeToSocket(&FLAG_BLOCK, 1, 0, 0);
            //Blockpage headers
            ecappeer.writeToSocket(blockHeaders.c_str(), blockHeaders.length(), 0, 0);
            //Read back msg recvd signal
            rc = ecappeer.readFromSocket(rBuf, 1, 0, 10);
/*#ifdef DGDEBUG
            std::cout << "Received from adapter: " << rBuf[0] << std::endl;
#endif*/
            if(rBuf[0] == FLAG_MSG_RECVD){
                o.fg[filtergroup]->getHTMLTemplate()->display(&ecappeer, &url,
                    checkme.whatIsNaughty, checkme.whatIsNaughtyCategories,
                    empty, &empty, &empty, &empty, 0, emptyS);
            }
            return 0;
        }

/*#ifdef DGDEBUG
        std::cout << "request URL/Header modified?: " << urlModified << "/" << headerModified << std::endl;
        url = requestHeader.getUrl(false, false);  //No MITM here - Squid does that
        logurl = requestHeader.getLogUrl(false, false);  //No MITM here - Squid does that
        urld = requestHeader.decode(url);
        urldomain = url.getHostname();
        std::cout << "After URL / Header modifications" << std::endl;
        std::cout << "requestType|url|logUrl|urld|urldomain: " << requestHeader.requestType() << '|'
            << url << '|' << logurl << '|' << urld << '|' << urldomain << std::endl;
#endif*/
        if(urlModified || headerModified){
/*#ifdef DGDEBUG
            std::cout << "Modifying request, getUrl() = " << requestHeader.getUrl() << std::endl;
            std::cout << "Modifying request, header.front() = " << requestHeader.header.front() << std::endl;
#endif*/            ecappeer.writeToSocket(&FLAG_MODIFY, 1, 0, 0);
            requestHeader.out(&ecappeer);
            return 0;
        }

    } catch (postfilter_exception &e){
/*#ifdef DGDEBUG
        std::cerr << dbgPeerPort << " -connection handler caught a POST filtering exception: " << e.what() << std::endl;
#endif*/
        syslog(LOG_ERR, "POST filtering exception: %s", e.what());
        //No need to call ecappeer.close() before returning.
        //The destructor for ecappeer is called up in FatController, which auto-closes the handle
        return 0;
    } catch (std::exception & e)    {
/*#ifdef DGDEBUG
        std::cerr << dbgPeerPort << " -connection handler caught an exception: " << e.what() << std::endl;
#endif*/
        //No need to call ecappeer.close() before returning.
        //The destructor for ecappeer is called up in FatController, which auto-closes the handle
        return 0;
    }

    //If none of the above scans discover a reason to block of modify,
    //then just allow the original request
    ecappeer.writeToSocket(&FLAG_USE_VIRGIN, 1, 0, 5, true, false);
    //No need to call ecappeer.close() before returning.
    //The destructor for ecappeer is called up in FatController, which auto-closes the handle
    return 0;
}

int ConnectionHandler::handleEcapRespmod(UDSocket &ecappeer){
    /*
    RESPMOD: Grab the response headers and body, then scan as necessary.
    If using the virgin response, send 'v' to ecappeer.
    If blocking, send 'b' to ecappeer, followed by new response headers and body.
    	This is the most difficult part - dumping data, then converting it to the necessary eCAP objects on the other side.
    	Maybe I should give the eCAP adapters a reference to a file which contains the raw 'this page is denied/blocked' html,
    	and have this method return nothing more than the 'b' followed by the reason it was denied.  eCAP adapters can use
    	canned response	headers and a regex to replace placeholder reasons with the real reasons.
    		*Seems like I would need two files: DeniedHeaders.txt and DeniedPage.txt
    		*One header per line in DeniedHeaders (for standardization and ease of use)
    		*Static data for DeniedPage.txt (read in, regex modify, dump data)
    	The other idea is for e2guardian to make two in-memory file handles with global access permissions
    		*One for headers
    		*One for denied page body
    		Send the file handles to the eCAP client and have it write back 'x' or something when it's done with them.
    */

	NaughtyFilter checkme;
	std::string mimetype("-");
	HTTPHeader requestHeader;
	//Set header read timeout - waiting forever is a bad thing
	requestHeader.setTimeout(o.pcon_timeout);
	HTTPHeader responseHeader;
	//Set header read timeout - waiting forever is a bad thing
	responseHeader.setTimeout(o.pcon_timeout);
	DataBuffer docbody;
	docbody.setTimeout(1);

	std::deque<CSPlugin*> responsescanners;
	bool isConnect;
	bool isHead;
	bool waschecked = false;
	bool isexception = false;
	bool isbypass = false;
	bool wasclean = false;
	bool cachehit = false;
	bool contentmodified = false;
	bool pausedtoobig = false;
	bool wasinfected = false;
	bool shouldScan = false;
	bool wasscanned = false;
	bool scanerror;
	filtergroup = 0;

	String url;
	String urld;
	String urldomain;

	// 0=none,1=first line,2=all
	int headersent = 0;
	off_t docsize = 0;  // to store the size of the returned document for logging
	int read = 0;

	std::string exceptionreason; // to hold the reason for not blocking
	std::string clientip("192.168.0.1");  // TODO: Decide whether the client IP is necessary for this system
	char* findResult;
	char ack[1];
	try{
		std::cout << getpid() << "Reading in request header" << std::endl;
		requestHeader.in(&ecappeer, true, true);

		std::cout << getpid() << "Finished reading response header" << std::endl;
		isConnect = requestHeader.requestType()[0] == 'C';
		isHead = requestHeader.requestType()[0] == 'H';

//		if(!isConnect && !isHead && o.fg[filtergroup]->disable_content_scan != 1) {
//			for (std::deque<Plugin *>::iterator i = o.csplugins_begin; i != o.csplugins_end; ++i)
//                	{
//				std::cout << "Checking CSPlugin_willScanRequest" << std::endl;
//                    		int csrc = ((CSPlugin*)(*i))->willScanRequest(requestHeader.getUrl(), clientuser.c_str(), filtergroup,
//                               		clientip.c_str(), false, false, isexception, isbypass);
//                    		if (csrc > 0) {
//					responsescanners.push_back((CSPlugin*)(*i));
//				}
//                    		else if (csrc < 0) {
//					syslog(LOG_ERR, "willScanRequest returned error: %d", csrc);
//				}
//                	}
#ifdef DGDEBUG
//	                std::cout << dbgPeerPort << " -Content scanners interested in response data: " << responsescanners.size() << std::endl;
#endif
//		}

        url = requestHeader.getUrl(false, false);  // << Need to remove the 'isssl' flag from this method and put it somewhere else
        urld = requestHeader.decode(url);
#ifdef DGDEBUG
        std::cout << getpid() << "Reading in response header" << std::endl;
#endif
        //The eCAP peer is going to just dump over the response header.  Therefore, read it in.
        responseHeader.in(&ecappeer, true, true);  // get header from eCAP client, allowing persistency and breaking on reloadconfig
#ifdef DEBUG
        std::cout << getpid() << "After reading in response header" << std::endl;
#endif
        // don't even bother scan testing if the content-length header indicates the file is larger than the maximum size we'll scan
        // - based on patch supplied by cahya (littlecahya@yahoo.de)
        // be careful: contentLength is signed, and max_content_filecache_scan_size is unsigned
        off_t cl = responseHeader.contentLength();
        if (!responsescanners.empty()) {
            if (cl == 0) {
				responsescanners.clear();
            } // Empty response need not be scanned
            else if ((cl > 0) && (cl > o.max_content_filecache_scan_size)) {
				responsescanners.clear();
			} // Too large?  Not scanning.
        }

        if (o.fg[filtergroup]->mitm_preservation_level) {
            shouldScan = true;
        }

        shouldScan = shouldScan || (cl != 0) && !isHead &&
            ((responseHeader.isContentType("text") || responseHeader.isContentType("-")) || !responsescanners.empty());

//#ifdef DGDEBUG
//		std::cout << "Flushing eCAP socket" << std::endl;
//#endif
//		//fdopen the socket
//		FILE* socketFile = fdopen(ecappeer.sck, "r+");
//		//fflush any extraneous data from the ecap adapter
//		int flushed = fflush(socketFile);
		char response;
//#ifdef DGDEBUG
//		std::cout << "eCAP socket flushed, result was : " << flushed << std::endl;
//#endif

//		char singleCharBuffer[1];
//		for(int sci = 0; sci < 10; sci++) {
//			std::cout << "Reading from socket, try #" << sci << std::endl;
//			try{
//			int scRead = ecappeer.readFromSocket(singleCharBuffer, 1, 0, 5, true, false);
//			if(scRead == -1) {
//				break;
//			} else{
//				std::cout << "Read " << scRead << "chars from socket" << std::endl;
//				std::cout << "Char was " << static_cast<int>(singleCharBuffer[0]) << std::endl;
//			}
//			} catch (std::exception e) {
//				std::cout << "Exception when trying to clear out the ecap socket" << std::endl;
//			}
//		}

#ifdef DEBUG
		std::cout << getpid() << "ShouldScan: " << schouldScan << std::endl;
#endif
		if(shouldScan) {
			ecappeer.writeToSocket(&FLAG_NEEDS_SCAN, 1, 0, 5, true, false);
#ifdef DGDEBUG
			std::cout << getpid() << "Waiting for FLAG_MSG_RECVD after sending FLAG_NEEDS_SCAN" << std::endl;
#endif
			read = ecappeer.readFromSocketn(ack, 1, 0, 5);
#ifdef DGDEBUG
			std::cout << getpid() << "After checking for FLAG_MSG_RECVD after sending FLAG_NEEDS_SCAN, read=" << read << std::endl;
#endif
			response = ack[0];
#ifdef DGDEBUG
			std::cout << getpid() << "Got response char" << std::endl;
#endif
			if(response != FLAG_MSG_RECVD) {
				std::string error;
				error.append("Received invalid FLAG_MSG_RECVD in response to FLAG_NEEDS_SCAN : '");
				error.append(std::string(1, response));
				error.append("', read ");
				error.append(std::to_string(read));
				error.append(" chars");
#ifdef DGDEBUG
				std::cout << getpid() << error.c_str() << read << std::endl;
#endif
				throw std::runtime_error(error);
			}
		} else {
			ecappeer.writeToSocket(&FLAG_USE_VIRGIN, 1, 0, 5, true, false);
#ifdef DGDEBUG
			std::cout << getpid() << "Waiting for FLAG_MSG_RECVD after sending FLAG_USE_VIRGIN" << std::endl;
#endif
			ecappeer.readFromSocketn(ack, 1, 0, 5);
			response = ack[0];
			if(response == FLAG_MSG_RECVD) {
				return 0;
			} else {
				std::string error;
				error.append("Received invalid FLAG_MSG_RECVD in response to FLAG_USE_VIRGIN : '");
				error.append(std::string(1, response));
				error.append("', read ");
				error.append(std::to_string(read));
				error.append(" chars");
				throw std::runtime_error(error);
			}
		}
#ifdef DGDEBUG
			std::cout << getpid() << "Checking whether response scanners are empty" << std::endl;
#endif
		//Re-check the response scanners now that the response header is available
		if (!responsescanners.empty())
                {
#ifdef DGDEBUG
                    std::cerr << getpid() << dbgPeerPort << " -Number of response CS plugins in candidate list: " << responsescanners.size() << std::endl;
#endif
                    //send header to plugin here needed
                    //also send user and group
#ifdef DGDEBUG
                    int j = 0;
#endif
                    std::deque<CSPlugin *> newplugins;
                    for (std::deque<CSPlugin *>::iterator i = responsescanners.begin(); i != responsescanners.end(); ++i)
                    {
                        int csrc = (*i)->willScanData(requestHeader.getUrl(), clientuser.c_str(), filtergroup, clientip.c_str(),
                        	false, false, false, false, responseHeader.disposition(), responseHeader.getContentType(), responseHeader.contentLength());
#ifdef DGDEBUG
                        std::cerr << getpid() << dbgPeerPort << " -willScanData for plugin " << j << " returned: " << csrc << std::endl;
#endif
                        if (csrc > 0) {
				newplugins.push_back(*i);
			}
                        else if (csrc < 0) {
				// TODO Should probably block on error
				syslog(LOG_ERR, "willScanData returned error: %d", csrc);
			}
#ifdef DGDEBUG
                        j++;
#endif
                    }
                    // Store only those plugins which responded positively to willScanData
                    responsescanners.swap(newplugins);
                }
#ifdef DGDEBUG
		std::cout << getpid() << "Checking whether response header is redirection or has auth required" << std::endl;
#endif
		if(!responseHeader.isRedirection() && !responseHeader.authRequired()) {
#ifdef DGDEBUG
		    std::cout << getpid() << "Response header was not redirection and no auth required" << std::endl;
#endif
		    bool download_exception = false;

            // Check the exception file site and MIME type lists.
            mimetype = responseHeader.getContentType().toCharArray();
#ifdef DGDEBUG
		    std::cout << getpid() << "Mimetype=" << mimetype << std::endl;
		    std::cout << getpid() << "urld=" << urld << std::endl;
#endif

            if (o.fg[filtergroup]->inExceptionFileSiteList(urld)) {
#ifdef DGDEBUG
                std::cout << getpid() << "InExceptionFileSiteList" << std::endl;
#endif
                download_exception = true;
		    } else {
                if (o.lm.l[o.fg[filtergroup]->exception_mimetype_list]->findInList(mimetype.c_str())) {
#ifdef DGDEBUG
                    std::cout << getpid() << "IsDownload_Exception" << std::endl;
#endif
                    download_exception = true;
                }
            }
                    // Perform banned MIME type matching
                    if (!download_exception) {
#ifdef DGDEBUG
		        std::cout << getpid() << "Not a download exception" << std::endl;
#endif
                        // If downloads are blanket blocked, block outright.
                        if (o.fg[filtergroup]->block_downloads) {
#ifdef DGDEBUG
		            std::cout << getpid() << "Block outright" << std::endl;
#endif
                            // did not match the exception list
                            checkme.whatIsNaughty = o.language_list.getTranslation(750);
                            // Blanket file download is active
                            checkme.whatIsNaughty += mimetype;
                            checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                            checkme.isItNaughty = true;
                            checkme.whatIsNaughtyCategories = "Blanket download block";
                        }
                        else if ((findResult = o.lm.l[o.fg[filtergroup]->banned_mimetype_list]->findInList(mimetype.c_str())) != NULL) {
#ifdef DGDEBUG
		            std::cout << getpid() << "Matched the banned list" << std::endl;
#endif
                            // matched the banned list
                            checkme.whatIsNaughty = o.language_list.getTranslation(800);
                            // Banned MIME Type:
                            checkme.whatIsNaughty += findResult;
                            checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                            checkme.isItNaughty = true;
                            checkme.whatIsNaughtyCategories = "Banned MIME Type";
                        }
#ifdef DGDEBUG
			std::cout << getpid() << "End of not download exception first" << std::endl;
                        std::cout << getpid() << " " << dbgPeerPort << mimetype.length() << std::endl;
                        std::cout << getpid() << " " << dbgPeerPort << " -:" << mimetype;
                        std::cout << getpid() << " " << dbgPeerPort << " -:" << std::endl;
#endif
                    }

                    // Perform extension matching - if not already matched the exception MIME or site lists
                    if (!download_exception) {
#ifdef DGDEBUG
		        std::cout << getpid() << "Performing Extension Matching" << std::endl;
#endif
                        // Can't ban file extensions of URLs that just redirect
                        String tempurl(urld);
                        String tempdispos(responseHeader.disposition());
                        unsigned int elist, blist;
                        elist = o.fg[filtergroup]->exception_extension_list;
                        blist = o.fg[filtergroup]->banned_extension_list;
                        char* e = NULL;
                        char* b = NULL;
                        if (tempdispos.length() > 1) {
                            // dispos filename must take presidense
#ifdef DGDEBUG
                            std::cout << getpid() << dbgPeerPort << " -Disposition filename:" << tempdispos << ":" << std::endl;
#endif
                            // The function expects a url so we have to
                            // generate a pseudo one.
                            tempdispos = "http://foo.bar/" + tempdispos;
                            e = o.fg[filtergroup]->inExtensionList(elist, tempdispos);
                            // Only need to check banned list if not blanket blocking
                            if ((e == NULL) && !(o.fg[filtergroup]->block_downloads)) {
                                b = o.fg[filtergroup]->inExtensionList(blist, tempdispos);
			    }
                        } else {
#ifdef DGDEBUG
		            std::cout << getpid() << "Tempdispos length less than 1" << std::endl;
#endif
                            if (!tempurl.contains("?")) {
                                e = o.fg[filtergroup]->inExtensionList(elist, tempurl);
                                if ((e == NULL) && !(o.fg[filtergroup]->block_downloads)) {
                                    b = o.fg[filtergroup]->inExtensionList(blist, tempurl);
				}
                            }
                            else if (String(mimetype.c_str()).contains("application/")) {
                                while (tempurl.endsWith("?")) {
                                    tempurl.chop();
                                }
                                while (tempurl.contains("/"))  	// no slash no url
                                {
                                    e = o.fg[filtergroup]->inExtensionList(elist, tempurl);
                                    if (e != NULL) {
                                        break;
				    }
                                    if (!(o.fg[filtergroup]->block_downloads)) {
                                        b = o.fg[filtergroup]->inExtensionList(blist, tempurl);
				    }
                                    while (tempurl.contains("/") && !tempurl.endsWith("?")) {
                                        tempurl.chop();
                                    }
                                    tempurl.chop();  // get rid of the ?
                                }
                            }
                        }

                        // If downloads are blanket blocked, block unless matched the exception list.
                        // If downloads are not blanket blocked, block if matched the banned list and not the exception list.
                        if (o.fg[filtergroup]->block_downloads && (e == NULL)) {
#ifdef DGDEBUG
		            std::cout << getpid() << "Block downloads, e == NULL" << std::endl;
#endif
                            // did not match the exception list
                            checkme.whatIsNaughty = o.language_list.getTranslation(751);
                            // Blanket file download is active
                            checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                            checkme.isItNaughty = true;
                            checkme.whatIsNaughtyCategories = "Blanket download block";
                        }
                        else if (!(o.fg[filtergroup]->block_downloads) && (e == NULL) && (b != NULL)) {
#ifdef DGDEBUG
		            std::cout << getpid() << "Not block downloads, e == NULL and b != NULL" << std::endl;
#endif
                            // matched the banned list
                            checkme.whatIsNaughty = o.language_list.getTranslation(900);
                            // Banned extension:
                            checkme.whatIsNaughty += b;
                            checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                            checkme.isItNaughty = true;
                            checkme.whatIsNaughtyCategories = "Banned extension";
                        }
                        else if (e != NULL) {
#ifdef DGDEBUG
		            std::cout << getpid() << "e != NULL" << std::endl;
#endif
                            // intention is to match either/or of the MIME & extension lists
                            // so if it gets this far, un-naughty it (may have been naughtied by the MIME type list)
                            checkme.isItNaughty = false;
                        }
                    }
		}

#ifdef DGDEBUG
		std::cout << getpid() << "!checkme.isItNaughty && (cl != 0) && !isHead" << std::endl;
#endif
		//Check response body if the mimetype check didn't come back naughty
                if (!checkme.isItNaughty && (cl != 0) && !isHead)  {
                    if (((responseHeader.isContentType("text") || responseHeader.isContentType("-"))) || !responsescanners.empty()) {
                        // don't search the cache if scan_clean_cache disabled & runav true (won't have been cached)
                        // also don't search cache for auth required headers (same reason)
                        // checkme: does not search the cache if scan_clean_cache is disabled break the fancy DM's bypass stuff?
                        // probably, since it uses a "magic" status code in the cache; easier than coding yet another hash type.
                        if (o.url_cache_number > 0 && (o.scan_clean_cache || responsescanners.empty()) && !responseHeader.authRequired()) {
                            if (wasClean(requestHeader, urld, filtergroup)) {
                                wasclean = true;
                                cachehit = true;
                                responsescanners.clear();
#ifdef DGDEBUG
                                std::cout << dbgPeerPort << " -url was clean skipping content and AV checking" << std::endl;
#endif
                            }
                        }
                        // despite the debug note above, we do still go through contentFilter for cached non-exception HTML,
                        // as content replacement rules need to be applied.
                        waschecked = true;
                        if (!responsescanners.empty()) {
#ifdef DGDEBUG
                            std::cout << dbgPeerPort << " -Filtering with expectation of a possible csmessage" << std::endl;
#endif
                            String csmessage;
                            contentFilter(&responseHeader, &requestHeader, &docbody, &ecappeer, &ecappeer, &headersent, &pausedtoobig,
                                          &docsize, &checkme, wasclean, filtergroup, responsescanners, &clientuser, &clientip,
                                          &wasinfected, &wasscanned, isbypass, urld, urldomain, &scanerror, contentmodified, &csmessage);
                            if (csmessage.length() > 0) {
#ifdef DGDEBUG
                                std::cout << dbgPeerPort << " -csmessage found: " << csmessage << std::endl;
#endif
                                exceptionreason = csmessage.toCharArray();
                            }
                        } else {
#ifdef DGDEBUG
			    std::cout << "-Filtering with no expectation of a csmessage" << std::endl;
#endif
                            contentFilter(&responseHeader, &requestHeader, &docbody, &ecappeer, &ecappeer, &headersent, &pausedtoobig,
                                          &docsize, &checkme, wasclean, filtergroup, responsescanners, &clientuser, &clientip,
                                          &wasinfected, &wasscanned, isbypass, urld, urldomain, &scanerror, contentmodified, NULL);
                        }
                    }
                }
#ifdef DGDEBUG
		std::cout << "WasNaughty? : " << checkme.isItNaughty << std::endl;
#endif
		if(!isexception && checkme.isException) {
			isexception = true;
			exceptionreason = checkme.whatIsNaughtyLog;
		}

		if (o.url_cache_number > 0) {
                	// add to cache if: wasn't already there, wasn't naughty, wasn't allowed by bypass/soft block, was text,
                	// was virus scanned and scan_clean_cache is enabled, was a GET request,
                	// and response was not a set of auth required headers (we haven't checked
                	// the actual content, just the proxy's auth error page!).
                	// also don't add "not modified" responses to the cache - if someone adds
                	// an entry and does a soft restart, we don't want the site to end up in
                	// the clean cache because someone who's already been to it hits refresh.
                	if (!wasclean && !checkme.isItNaughty
                        	&& (responseHeader.isContentType("text") || (wasscanned && o.scan_clean_cache))
                        	&& (requestHeader.requestType() == "GET") && (responseHeader.returnCode() == 200)
                        	&& urld.length() < 2000)
                	{
             			addToClean(urld, filtergroup);
                	}
                }

        // Need new logic.
        // Possibilities:
        /*
        1: Not modifying, not naughty: use virgin
        2: Not modifying, was naughty: block
        3: Modifying, not naughty: Modify - new response headers, but original body
        4: Modifying, was naughty: Modify - new response headers, but blockpage body
        */
        bool responseHeaderModified = false;
        //This is where you scan response headers for things to remove
        if (o.fg[filtergroup]->mitm_preservation_level) {
            responseHeaderModified = responseHeader.applyMitmPreservationLevel(o.fg[filtergroup]->mitm_preservation_level);
        }

        std::string empty("");
        String emptyS(empty.c_str());
        if (checkme.isItNaughty) {  // CASE 1: Block Response Content
            ecappeer.writeToSocket(&FLAG_MODIFY, 1, 0, 5, true, false);
#ifdef DGDEBUG
            std::cout << "Waiting for FLAG_MSG_RECVD after determining isItNaughty = true" << std::endl;
#endif
            ecappeer.readFromSocketn(ack, 1, 0, 1);
            if(ack[0] == FLAG_MSG_RECVD) {  // write blockpage headers
                ecappeer.writeToSocket(blockHeaders.c_str(), blockHeaders.length(), 0, 0);
            } else {
                throw std::runtime_error("Received invalid FLAG_MSG_RECVD after isItNaughty = true : " + std::string(1, ack[0]));
            }
            // after writing the blockpage headers, wait for the FLAG_MSG_RECVD again
            ecappeer.readFromSocketn(ack, 1, 0, 1);
            if(ack[0] == FLAG_MSG_RECVD) {
                //write blockpage
                o.fg[filtergroup]->getHTMLTemplate()->display(&ecappeer, &url,
                    checkme.whatIsNaughty, checkme.whatIsNaughtyCategories,
                    empty, &empty, &empty, &empty, 0, emptyS);
            } else {
                throw std::runtime_error("Received invalid FLAG_MSG_RECVD after sending blockpage headers : " + std::string(1, ack[0]));
            }
            //Read from the socket to block and keep it open until the ecap adapter has read the whole blockpage
            ecappeer.readFromSocketn(ack, 1, 0, 1);
            return 0;
        } else if (responseHeaderModified) {  // CASE 2: Response Headers Modified
            ecappeer.writeToSocket(&FLAG_MODIFY, 1, 0, 5, true, false);
#ifdef DGDEBUG
            std::cout << "Waiting for FLAG_MSG_RECVD after determining wasNaughty = false and modifyResponse = true" << std::endl;
#endif
            ecappeer.readFromSocketn(ack, 1, 0, 1);
            if(ack[0] == FLAG_MSG_RECVD) {  // write modified headers
                responseHeader.out(&ecappeer);
            } else {
                throw std::runtime_error("Received invalid FLAG_MSG_RECVD after isItNaughty = true : " + std::string(1, ack[0]));
            }
            // after writing the modified headers, wait for the FLAG_MSG_RECVD again
            ecappeer.readFromSocketn(ack, 1, 0, 1);
            if(ack[0] == FLAG_MSG_RECVD) {
                //write back the document body (might have been modified along the way)
                docbody.out(&ecappeer);
            } else {
                throw std::runtime_error("Received invalid FLAG_MSG_RECVD after sending blockpage headers : " + std::string(1, ack[0]));
            }
            //Read from the socket to block and keep it open until the ecap adapter has read the whole blockpage
            ecappeer.readFromSocketn(ack, 1, 0, 1);
            return 0;
        } else {  // CASE 3: Allow Original Response
            ecappeer.writeToSocket(&FLAG_USE_VIRGIN, 1, 0, 5, true, false);
#ifdef DGDEBUG
            std::cout << "Waiting for FLAG_MSG_RECVD after determining isItNaughty = false" << std::endl;
#endif
            ecappeer.readFromSocketn(ack, 1, 0, 1);
            if(ack[0] == FLAG_MSG_RECVD) {
                return 0;
            } else {
                throw std::runtime_error("Received invalid FLAG_MSG_RECVD after isItNaughty = false : " + std::string(1, ack[0]));
            }
            return 0;
        }
    } catch (std::exception & e)    {
#ifdef DGDEBUG
        std::cerr << dbgPeerPort << " -connection handler caught an exception: " << e.what() << std::endl;
#endif
        //No need to call ecappeer.close() before returning.
        //The destructor for ecappeer is called up in FatController, which auto-closes the handle
        return 0;
    }

	//Currently just sending back the 'use virgin' signal for testing
	ecappeer.writeToSocket(&FLAG_USE_VIRGIN, 1, 0, 5, true, false);
#ifdef DGDEBUG
			std::cout << "Waiting for FLAG_MSG_RECVD after sending catchall FLAG_USE_VIRGIN" << std::endl;
#endif
	ecappeer.readFromSocketn(ack, 1, 0, 5);
	if(ack[0] == FLAG_MSG_RECVD) {
		return 0;
	} else {
		throw std::runtime_error("Received invalid FLAG_MSG_RECVD in response to catchall FLAG_USE_VIRGIN : " + std::string(1, ack[0]));
	}
}

// pass data between proxy and client, filtering as we go.
// this is the only public function of ConnectionHandler
int ConnectionHandler::handlePeer(Socket &peerconn, String &ip)
{
    persistent_authed = false;

#ifdef DGDEBUG
    // for debug info only - TCP peer port
    dbgPeerPort = peerconn.getPeerSourcePort();
#endif
    Socket proxysock;

    return handleConnection(peerconn, ip, false, proxysock);
}


// all content blocking/filtering is triggered from calls inside here
int ConnectionHandler::handleConnection(Socket &peerconn, String &ip, bool ismitm, Socket &proxysock)
{
    struct timeval thestart;
    gettimeofday(&thestart, NULL);

    peerconn.setTimeout(o.proxy_timeout);

    HTTPHeader docheader;  // to hold the returned page header from proxy
    HTTPHeader header;  // to hold the incoming client request header

    // set a timeout as we don't want blocking 4 eva
    // this also sets how long a peerconn will wait for other requests
    header.setTimeout(o.pcon_timeout);
    docheader.setTimeout(o.exchange_timeout);

    // to hold the returned page
    DataBuffer docbody;
    docbody.setTimeout(o.proxy_timeout);

    // flags
    bool waschecked = false;
    bool wasrequested = false;
    bool isexception = false;
    bool isourwebserver = false;
    bool wasclean = false;
    bool cachehit = false;
    bool isbypass = false;
    bool iscookiebypass = false;
    bool isvirusbypass = false;
    bool isscanbypass = false;
    bool ispostblock = false;
    bool pausedtoobig = false;
    bool wasinfected = false;
    bool wasscanned = false;
    bool contentmodified = false;
    bool urlmodified = false;
    bool headermodified = false;
    bool headeradded = false;
    bool isconnect;
    bool ishead;
    bool scanerror;
    bool ismitmcandidate = false;
    bool do_mitm = false;
    bool is_ssl = false;
    int bypasstimestamp = 0;
    bool urlredirect = false;

    // 0=none,1=first line,2=all
    int headersent = 0;
    int message_no = 0;

    // Content scanning plugins to use for request (POST) & response data
    std::deque<CSPlugin*> requestscanners;
    std::deque<CSPlugin*> responsescanners;

    std::string mimetype("-");

    String url;
    String logurl;
    String urld;
    String urldomain;

    std::string exceptionreason;  // to hold the reason for not blocking
    std::string exceptioncat;

    off_t docsize = 0;  // to store the size of the returned document for logging

    std::string clientip(ip.toCharArray());  // hold the clients ip

    delete clienthost;

    clienthost = NULL;  // and the hostname, if available
    matchedip = false;

    // clear list of parameters extracted from URL
    urlparams.clear();

    // clear out info about POST data
    postparts.clear();

#ifdef DGDEBUG			// debug stuff surprisingly enough
    std::cout << dbgPeerPort << " -got peer connection" << std::endl;
    std::cout << dbgPeerPort << clientip << std::endl;
#endif
    // proxysock now passed to function
    // Socket proxysock;

    try    {
        int rc;

#ifdef DGDEBUG
        int pcount = 0;
#endif

        // assume all requests over the one persistent connection are from
        // the same user. means we only need to query the auth plugin until
        // we get credentials, then assume they are valid for all reqs. on
        // the persistent connection.
        std::string oldclientuser;
        std::string room;

        int oldfg = 0, gmode;
        bool authed = false;
        bool isbanneduser = false;

        FDTunnel fdt;
        NaughtyFilter checkme;
        AuthPlugin* auth_plugin = NULL;

        // RFC states that connections are persistent
        bool persistOutgoing = true;
        bool persistPeer = true;
        bool persistProxy = true;

        bool firsttime = true;
        header.in(&peerconn, true, true);  // get header from client, allowing persistency and breaking on reloadconfig
//
// End of set-up section
//
// Start of main loop
//

        // maintain a persistent connection
        while ((firsttime || persistPeer) && !reloadconfig)        {
#ifdef DGDEBUG
            std::cout << " firsttime =" << firsttime << "ismitm =" << ismitm << " clientuser =" << clientuser << " group = " << filtergroup << std::endl;
#endif
            if (firsttime)            {
                // reset flags & objects next time round the loop
                firsttime = false;

                // quick trick for the very first connection :-)
                if (!ismitm)
                    persistProxy = false;
            }            else            {
                // another round...
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -persisting (count " << ++pcount << ")" << std::endl;
                syslog(LOG_ERR, "Served %d requests on this connection so far - ismitm=%d", pcount, ismitm);
                std::cout << dbgPeerPort << " - " << clientip << std::endl;
#endif
                header.reset();
                try                {
                    header.in(&peerconn, true, true);  // get header from client, allowing persistency and breaking on reloadconfig
                }                catch (std::exception &e)                {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -Persistent connection closed" << std::endl;
#endif
                    break;
                }

                // we will actually need to do *lots* of resetting of flags etc. here for pconns to work
                gettimeofday(&thestart, NULL);



                waschecked = false;  // flags
                wasrequested = false;
                isexception = false;
                isourwebserver = false;
                wasclean = false;
                cachehit = false;
                isbypass = false;
                iscookiebypass = false;
                isvirusbypass = false;
                bypasstimestamp = 0;
                isscanbypass = false;
                ispostblock = false;
                pausedtoobig = false;
                wasinfected = false;
                wasscanned = false;
                contentmodified = false;
                urlmodified = false;
                headermodified = false;
                headeradded = false;
                urlredirect = false;

                authed = false;
                isbanneduser = false;

                requestscanners.clear();
                responsescanners.clear();

                headersent = 0;  // 0=none,1=first line,2=all
                delete clienthost;
                clienthost = NULL;  // and the hostname, if available
                matchedip = false;
                urlparams.clear();
                postparts.clear();
                docsize = 0;  // to store the size of the returned document for logging
                message_no = 0;
                mimetype = "-";
                exceptionreason = "";
                exceptioncat = "";
                room = "";

                // reset docheader & docbody
                // headers *should* take care of themselves on the next in()
                // actually not entirely true for docheader - we may read
                // certain properties of it (in denyAccess) before we've
                // actually performed the next in(), so make sure we do a full
                // reset now.
                docheader.reset();
                docbody.reset();

                // our filter
                checkme.reset();
            }

            url = header.getUrl(false, ismitm);
            logurl = header.getLogUrl(false, ismitm);
            urld = header.decode(url);
            urldomain = url.getHostname();
            is_ssl = header.requestType().startsWith("CONNECT");

            //If proxy connction is not persistent...
            if (!persistProxy)            {
                try                {
                    // ...connect to proxy
                    for (int i = 0; i < o.proxy_timeout; i++)                    {
                        rc = proxysock.connect(o.proxy_ip, o.proxy_port);
                        if (!rc)                        {
                            break;
                        }                        else                        {
                            sleep(1);
                        }
                    }
                    if (rc)                    {
#ifdef DGDEBUG
                        std::cerr << dbgPeerPort << " -Error connecting to proxy" << std::endl;
#endif
//                                                syslog(LOG_ERR, "Error connecting to proxy - ip client: %s destination: %s - %s", clientip.c_str(), urldomain.c_str(),strerror(errno));
                        return 3;
                    }
                }
                catch (std::exception & e)                {
#ifdef DGDEBUG
                    std::cerr << dbgPeerPort << " -exception while creating proxysock: " << e.what() << std::endl;
#endif
                }
            }

#ifdef DGDEBUG
            std::cerr << getpid() << "Start URL " << url.c_str() << "is_ssl=" << is_ssl << "ismitm=" << ismitm << std::endl;
#endif

            // checks for bad URLs to prevent security holes/domain obfuscation.
            if (header.malformedURL(url))
            {
                try                {
                    // writestring throws exception on error/timeout
                    peerconn.writeString("HTTP/1.0 400 Bad Request\nContent-Type: text/html\n\n");
                    peerconn.writeString("<HTML><HEAD><TITLE>e2guardian - 400 Bad Request</TITLE></HEAD><BODY><H1>e2guardian - 400 Bad Request</H1>");
                    message_no = 200;
                    // The requested URL is malformed.
                    peerconn.writeString(o.language_list.getTranslation(200));
                    peerconn.writeString("</BODY></HTML>\n");
                }
                catch (std::exception & e)                {
                }
                break;
            }

            urld = header.decode(url);

            if (urldomain == "internal.test.e2guardian.org")            {
                try  	// writestring throws exception on error/timeout
                {
                    peerconn.writeString("HTTP/1.0 200 \nContent-Type: text/html\n\n<HTML><HEAD><TITLE>e2guardian internal test</TITLE></HEAD><BODY><H1>e2guardian internal test OK</H1> ");
                    peerconn.writeString("</BODY></HTML>\n");
                }
                catch (std::exception & e)                {
                }
                proxysock.close();  // close connection to proxy
                break;
            }

// do total block list checking here
            if (o.use_total_block_list && o.inTotalBlockList(urld))            {
                //if ( header.requestType().startsWith("CONNECT"))
                if (is_ssl )                {
                    try  	// writestring throws exception on error/timeout
                    {
                        peerconn.writeString("HTTP/1.0 404 Banned Site\nContent-Type: text/html\n\n<HTML><HEAD><TITLE>Protex - Banned Site</TITLE></HEAD><BODY><H1>Protex - Banned Site</H1> ");
                        peerconn.writeString(logurl.c_str());
                        // The requested URL is malformed.
                        peerconn.writeString("</BODY></HTML>\n");
                    }
                    catch (std::exception & e)                    {
                    }
                }                else    // write blank graphic
                {
                    try                    {                        peerconn.writeString("HTTP/1.0 200 OK\n");
                    }
                    catch (std::exception & e)                    {
                    }
                    o.banned_image.display(&peerconn);
                }
                proxysock.close();  // close connection to proxy
                break;
            }

            // don't let the client connection persist if the client doesn't want it to.
            persistOutgoing = header.isPersistent();
//
//
// Start of Authentication Checks
//
//
            // don't have credentials for this connection yet? get some!
            if (!persistent_authed)            {
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -Not got persistent credentials for this connection - querying auth plugins" << std::endl;
#endif
                bool dobreak = false;
                if (o.authplugins.size() != 0)                {
                    // We have some auth plugins load
                    int authloop = 0;
                    String tmp;

                    for (std::deque<Plugin*>::iterator i = o.authplugins_begin; i != o.authplugins_end; i++)                    {
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -Querying next auth plugin..." << std::endl;
#endif
                        // try to get the username & parse the return value
                        auth_plugin = (AuthPlugin*)(*i);

                        // auth plugin selection for multi ports
//
//
// Logic changed to allow auth scan with multiple ports as option to auth-port
//       fixed mapping
//
                        if (o.map_auth_to_ports)                        {
                            if (o.filter_ports.size() > 1)                            {
                                tmp = o.auth_map[peerconn.getPort()];
                            }
                            else                            {
                                // auth plugin selection for one port
                                tmp = o.auth_map[authloop];
                                authloop++;
                            }

                            if (tmp.compare(auth_plugin->getPluginName().toCharArray()) == 0)                            {
                                rc = auth_plugin->identify(peerconn, proxysock, header, clientuser);
                            }
                            else                            {
                                rc = DGAUTH_NOMATCH;
                            }
                        }
                        else                        {
                            rc = auth_plugin->identify(peerconn, proxysock, header, clientuser);
                        }

                        if (rc == DGAUTH_NOMATCH)                        {
#ifdef DGDEBUG
                            std::cout<<"Auth plugin did not find a match; querying remaining plugins"<<std::endl;
#endif
                            continue;
                        }
                        else if (rc == DGAUTH_REDIRECT)                        {
#ifdef DGDEBUG
                            std::cout<<"Auth plugin told us to redirect client to \"" << clientuser << "\"; not querying remaining plugins"<<std::endl;
#endif
                            // ident plugin told us to redirect to a login page
                            String writestring("HTTP/1.0 302 Redirect\r\nLocation: ");
                            writestring += clientuser;
                            writestring += "\r\n\r\n";
                            peerconn.writeString(writestring.toCharArray());
                            dobreak = true;
                            break;
                        }
                        else if (rc == DGAUTH_OK_NOPERSIST)                        {
#ifdef DGDEBUG
                            std::cout<<"Auth plugin  returned OK but no persist not setting persist auth"<<std::endl;
#endif
                            overide_persist = true;
                        }
                        else if (rc < 0)                        {
                            if (!is_daemonised)
                                std::cerr<<"Auth plugin returned error code: "<<rc<<std::endl;
                            syslog(LOG_ERR,"Auth plugin returned error code: %d", rc);
                            dobreak = true;
                            break;
                        }
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -Auth plugin found username " << clientuser << " (" << oldclientuser << "), now determining group" << std::endl;
#endif
                        if (clientuser == oldclientuser)                        {
#ifdef DGDEBUG
                            std::cout << dbgPeerPort << " -Same user as last time, re-using old group no." << std::endl;
#endif
                            authed = true;
                            filtergroup = oldfg;
                            break;
                        }
                        // try to get the filter group & parse the return value
                        rc = auth_plugin->determineGroup(clientuser, filtergroup);
                        if (rc == DGAUTH_OK)                        {
#ifdef DGDEBUG
                            std::cout<<"Auth plugin found username & group; not querying remaining plugins"<<std::endl;
#endif
                            authed = true;
                            break;
                        }
                        else if (rc == DGAUTH_NOMATCH)                        {
#ifdef DGDEBUG
                            std::cout<<"Auth plugin did not find a match; querying remaining plugins"<<std::endl;
#endif
                            continue;
                        }
                        else if (rc == DGAUTH_NOUSER)                        {
#ifdef DGDEBUG
                            std::cout<<"Auth plugin found username \"" << clientuser << "\" but no associated group; not querying remaining plugins"<<std::endl;
#endif
                            filtergroup = 0;  //default group - one day configurable?
                            authed = true;
                            break;
                        }
                        else if (rc < 0)                        {
                            if (!is_daemonised)
                                std::cerr<<"Auth plugin returned error code: "<<rc<<std::endl;
                            syslog(LOG_ERR,"Auth plugin returned error code: %d", rc);
                            dobreak = true;
                            break;
                        }
                    } // end of querying all plugins (for)

                    // break the peer loop
                    if (dobreak)
                        break;

                    if ((!authed) || (filtergroup < 0) || (filtergroup >= o.numfg))                    {
#ifdef DGDEBUG
                        if (!authed)
                            std::cout << dbgPeerPort << " -No identity found; using defaults" << std::endl;
                        else
                            std::cout << dbgPeerPort << " -Plugin returned out-of-range filter group number; using defaults" << std::endl;
#endif
                        // If none of the auth plugins currently loaded rely on querying the proxy,
                        // such as 'ident' or 'ip', then pretend we're authed. What this flag
                        // actually controls is whether or not the query should be forwarded to the
                        // proxy (without pre-emptive blocking); we don't want this for 'ident' or
                        // 'ip', because Squid isn't necessarily going to return 'auth required'.
                        authed = !o.auth_needs_proxy_query;
#ifdef DGDEBUG
                        if (!o.auth_needs_proxy_query)
                            std::cout << dbgPeerPort << " -No loaded auth plugins require parent proxy queries; enabling pre-emptive blocking despite lack of authentication" << std::endl;
#endif
                        clientuser = "-";
                        filtergroup = 0;  //default group - one day configurable?
                    }                    else                    {
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -Identity found; caching username & group" << std::endl;
#endif
                        if (auth_plugin->is_connection_based && !overide_persist)                        {
#ifdef DGDEBUG
                            std::cout<<"Auth plugin is for a connection-based auth method - keeping credentials for entire connection"<<std::endl;
#endif
                            persistent_authed = true;
                        }
                        oldclientuser = clientuser;
                        oldfg = filtergroup;
                    }
                }                else                {
                    // We don't have any auth plugins loaded
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -No auth plugins loaded; using defaults & feigning persistency" << std::endl;
#endif
                    authed = true;
                    clientuser = "-";
                    filtergroup = 0;
                    persistent_authed = true;
                }
            }            else            {
                // persistent_authed == true
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -Already got credentials for this connection - not querying auth plugins" << std::endl;
#endif
                authed = true;
            }

            gmode = o.fg[filtergroup]->group_mode;

#ifdef DGDEBUG
            std::cout << dbgPeerPort << " -username: " << clientuser << std::endl;
            std::cout << dbgPeerPort << " -filtergroup: " << filtergroup << std::endl;
            std::cout << dbgPeerPort << " -groupmode: " << gmode << std::endl;
#endif
//
//
// End of Authentication Checking
//
//

//
//
// Now check if user or machine is banned and room-based checking
//
//
            // filter group modes are: 0 = banned, 1 = filtered, 2 = exception.
            // is this user banned?
            isbanneduser = (gmode == 0);

            if (o.use_xforwardedfor)            {
                bool use_xforwardedfor;
                if ( o.xforwardedfor_filter_ip.size() > 0 )                {
                    use_xforwardedfor = false;
                    for (unsigned int i = 0; i < o.xforwardedfor_filter_ip.size(); i++)                    {
                        if (strcmp(clientip.c_str(),o.xforwardedfor_filter_ip[i].c_str()) == 0)                        {
                            use_xforwardedfor = true;
                            break;
                        }
                    }
                }                else                {
                    use_xforwardedfor = true;
                }
                if (use_xforwardedfor == 1)                {
                    std::string xforwardip(header.getXForwardedForIP());
                    if (xforwardip.length() > 6)                    {
                        clientip = xforwardip;
                    }
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -using x-forwardedfor:" << clientip << std::endl;
#endif
                }
            }

            // is this machine banned?
            bool isbannedip = o.inBannedIPList(&clientip, clienthost);
            bool part_banned;
            if (isbannedip)
                matchedip = clienthost == NULL;
            else            {
                if (o.inRoom(clientip, room, clienthost, &isbannedip, &part_banned, &isexception, urld))                {
#ifdef DGDEBUG
                    std::cout <<  " isbannedip = " << isbannedip << "ispart_banned = " << part_banned << " isexception = " << isexception << std::endl;
#endif
                    if (isbannedip)                    {
                        matchedip = clienthost == NULL;
                    }
                    if (isexception)                    {
                        // do reason codes etc
                        exceptionreason = o.language_list.getTranslation(630);
                        exceptionreason.append(room);
                        exceptionreason.append( o.language_list.getTranslation(631));
                        message_no = 632;
                    }
                }
            }

            if (o.forwarded_for)            {
                header.addXForwardedFor(clientip);  // add squid-like entry
            }

#ifdef ENABLE_ORIG_IP
            // if working in transparent mode and grabbing of original IP addresses is
            // enabled, does the original IP address match one of those that the host
            // we are going to resolves to?
            // Resolves http://www.kb.cert.org/vuls/id/435052
            if (o.get_orig_ip)
            {
                // XXX This will currently only work on Linux/Netfilter.
                sockaddr_in origaddr;
                socklen_t origaddrlen(sizeof(sockaddr_in));
                // Note: we assume that for non-redirected connections, this getsockopt call will
                // return the proxy server's IP, and not -1.  Hence, comparing the result with
                // the return value of Socket::getLocalIP() should tell us that the client didn't
                // connect transparently, and we can assume they aren't vulnerable.
                if (getsockopt(peerconn.getFD(), SOL_IP, SO_ORIGINAL_DST, &origaddr, &origaddrlen) < 0)
                {
                    syslog(LOG_ERR, "Failed to get client's original destination IP: %s", strerror(errno));
                    break;
                }

                std::string orig_dest_ip(inet_ntoa(origaddr.sin_addr));
                if (orig_dest_ip == peerconn.getLocalIP())
                {
                    // The destination IP before redirection is the same as the IP the
                    // client has actually been connected to - they aren't connecting transparently.
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -SO_ORIGINAL_DST and getLocalIP are equal; client not connected transparently" << std::endl;
#endif
                }
                else
                {
                    // Look up domain from request URL, and check orig IP against resolved IPs
                    addrinfo hints;
                    memset(&hints, 0, sizeof(hints));
                    hints.ai_family = AF_INET;
                    hints.ai_socktype = SOCK_STREAM;
                    hints.ai_protocol = IPPROTO_TCP;
                    addrinfo *results;
                    int result = getaddrinfo(urldomain.c_str(), NULL, &hints, &results);
                    if (result)
                    {
                        freeaddrinfo(results);
                        syslog(LOG_ERR, "Cannot resolve hostname for host header checks: %s", gai_strerror(errno));
                        break;
                    }
                    addrinfo *current = results;
                    bool matched = false;
                    while (current != NULL)
                    {
                        if (orig_dest_ip == inet_ntoa(((sockaddr_in*)(current->ai_addr))->sin_addr))
                        {
#ifdef DGDEBUG
                            std::cout << dbgPeerPort << urldomain << " matched to original destination of " << orig_dest_ip << std::endl;
#endif
                            matched = true;
                            break;
                        }
                        current = current->ai_next;
                    }
                    freeaddrinfo(results);
                    if (!matched)
                    {
                        // Host header/URL said one thing, but the original destination IP said another.
                        // This is exactly the vulnerability we want to prevent.
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << urldomain << " DID NOT MATCH original destination of " << orig_dest_ip << std::endl;
#endif
                        syslog(LOG_ERR, "Destination host of %s did not match the original destination IP of %s", urldomain.c_str(), orig_dest_ip.c_str());
                        try                        {
                            // writestring throws exception on error/timeout
                            peerconn.writeString("HTTP/1.0 400 Bad Request\nContent-Type: text/html\n\n");
                            peerconn.writeString("<HTML><HEAD><TITLE>e2guardian - 400 Bad Request</TITLE></HEAD><BODY><H1>e2guardian - 400 Bad Request</H1>");

                            // The requested URL is malformed.
                            peerconn.writeString(o.language_list.getTranslation(200));
                            peerconn.writeString("</BODY></HTML>\n");
                        }
                        catch (std::exception & e)                        {
                        }
                        break;
                    }
                }
            }
#endif


//
// Start of by pass
//

            if (header.isScanBypassURL(&url, o.fg[filtergroup]->magic.c_str(), clientip.c_str())){
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -Scan Bypass URL match" << std::endl;
#endif
                isscanbypass = true;
                isbypass = true;
                exceptionreason = o.language_list.getTranslation(608);
            }
            else if ((o.fg[filtergroup]->bypass_mode != 0) || (o.fg[filtergroup]->infection_bypass_mode != 0)){
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -About to check for bypass..." << std::endl;
#endif
                if (o.fg[filtergroup]->bypass_mode != 0){
                    bypasstimestamp = header.isBypassURL(&url, o.fg[filtergroup]->magic.c_str(), clientip.c_str(), NULL);
				}
                if ((bypasstimestamp == 0) && (o.fg[filtergroup]->infection_bypass_mode != 0)){
                    bypasstimestamp = header.isBypassURL(&url, o.fg[filtergroup]->imagic.c_str(), clientip.c_str(), &isvirusbypass);
				}
                if (bypasstimestamp > 0)                {
#ifdef DGDEBUG
                    if (isvirusbypass){
                        std::cout << dbgPeerPort << " -Infection bypass URL match" << std::endl;
					}
                    else{
                        std::cout << dbgPeerPort << " -Filter bypass URL match" << std::endl;
					}
#endif
                    header.chopBypass(url, isvirusbypass);
                    if (bypasstimestamp > 1)  	// not expired
                    {
                        isbypass = true;
                        // checkme: need a TR string for virus bypass
                        exceptionreason = o.language_list.getTranslation(606);
                    }
                }
                else if (o.fg[filtergroup]->bypass_mode != 0)                {
                    if (header.isBypassCookie(urldomain, o.fg[filtergroup]->cookie_magic.c_str(), clientip.c_str()))
                    {
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -Bypass cookie match" << std::endl;
#endif
                        iscookiebypass = true;
                        isbypass = true;
                        isexception = true;
                        exceptionreason = o.language_list.getTranslation(607);
                    }
                }
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -Finished bypass checks." << std::endl;
#endif
            }

#ifdef DGDEBUG
            if (isbypass)            {
                std::cout << dbgPeerPort << " -Bypass activated!" << std::endl;
            }
#endif
//
// End of bypass
//
// Start of scan by pass
//

            if (isscanbypass)            {
                //we need to decode the URL and send the temp file with the
                //correct header to the client then delete the temp file
                String tempfilename(url.after("GSBYPASS=").after("&N="));
                String tempfilemime(tempfilename.after("&M="));
                String tempfiledis(header.decode(tempfilemime.after("&D="), true));
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -Original filename: " << tempfiledis << std::endl;
#endif
                String rtype(header.requestType());
                tempfilemime = tempfilemime.before("&D=");
                tempfilename = o.download_dir + "/tf" + tempfilename.before("&M=");
                try                {
                    docsize = sendFile(&peerconn, tempfilename, tempfilemime, tempfiledis, url);
                    header.chopScanBypass(url);
                    url = header.getUrl();
                    //urld = header.decode(url);  // unneeded really

                    doLog(clientuser, clientip, logurl, header.port, exceptionreason,
                          rtype, docsize, NULL, false, 0, isexception, false, &thestart,
                          cachehit, 200, mimetype, wasinfected, wasscanned, 0, filtergroup,
                          &header);

                    if (o.delete_downloaded_temp_files)                    {
                        unlink(tempfilename.toCharArray());
                    }
                }
                catch (std::exception & e)                {
                }
                persistProxy = false;
                proxysock.close();  // close connection to proxy
                break;
            }
//
// End of scan by pass
//


            char *retchar;

//
// Start of exception checking
//
            // being a banned user/IP overrides the fact that a site may be in the exception lists
            // needn't check these lists in bypass modes
            if (!(isbanneduser || isbannedip || isbypass || isexception ))            {
                //bool is_ssl = header.requestType() == "CONNECT";
                bool is_ip = isIPHostnameStrip(urld);
                if ((gmode == 2))  	// admin user
                {
                    isexception = true;
                    exceptionreason = o.language_list.getTranslation(601);
                    message_no = 601;
                    // Exception client user match.
                }
                else if (o.inExceptionIPList(&clientip, clienthost))  	// admin pc
                {
                    matchedip = clienthost == NULL;
                    isexception = true;
                    exceptionreason = o.language_list.getTranslation(600);
                    // Exception client IP match.
                }
                if (!isexception && (*o.fg[filtergroup]).enable_local_list)                {

                    if (is_ssl && (!ismitmcandidate) && ((retchar = o.fg[filtergroup]->inLocalBannedSSLSiteList(urld, false, is_ip, is_ssl)) != NULL))  	// blocked SSL site
                    {
                        checkme.whatIsNaughty = o.language_list.getTranslation(580);  // banned site
                        message_no = 580;
                        checkme.whatIsNaughty += retchar;
                        checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                        checkme.isItNaughty = true;
                        checkme.whatIsNaughtyCategories = (*o.lm.l[o.fg[filtergroup]->local_banned_ssl_site_list]).lastcategory.toCharArray();
                    }
                    else if (o.fg[filtergroup]->inLocalExceptionSiteList(urld, false, is_ip, is_ssl))  	// allowed site
                    {
                        if (o.fg[0]->isOurWebserver(url))                        {
                            isourwebserver = true;
                        }                        else                        {
                            isexception = true;
                            exceptionreason = o.language_list.getTranslation(662);
                            message_no = 662;
                            // Exception site match.
                            exceptioncat = o.lm.l[o.fg[filtergroup]->local_exception_site_list]->lastcategory.toCharArray();
                        }
                    }
                    else if (o.fg[filtergroup]->inLocalExceptionURLList(urld, false, is_ip, is_ssl))  	// allowed url
                    {
                        isexception = true;
                        exceptionreason = o.language_list.getTranslation(663);
                        message_no = 663;
                        // Exception url match.
                        exceptioncat = o.lm.l[o.fg[filtergroup]->local_exception_url_list]->lastcategory.toCharArray();
                    }
                    else if ((!is_ssl) && embededRefererChecks(&header, &urld, &url, filtergroup))   // referer exception
                    {
                        isexception = true;
                        exceptionreason = o.language_list.getTranslation(620);
                        message_no = 620;
                    }
                    // end of local lists exception checking
                }
            }


            if ((*o.fg[filtergroup]).enable_local_list)            {
                if (authed && !(isexception || isourwebserver))                {
                    // check if this is a search request
                    if (!is_ssl) checkme.isSearch = header.isSearch(filtergroup);
                    // add local grey and black checks
                    if (!ismitmcandidate || o.fg[filtergroup]->only_mitm_ssl_grey)                    {
                        requestLocalChecks(&header, &checkme, &urld, &url, &clientip, &clientuser, filtergroup, isbanneduser, isbannedip, room);
                        message_no = checkme.message_no;
                    };
                };
            }
            // orginal section only now called if local list not matched
            if (!(isbanneduser || isbannedip || isbypass || isexception || checkme.isGrey || checkme.isItNaughty || o.fg[filtergroup]->use_only_local_allow_lists ))            {
                //bool is_ssl = header.requestType() == "CONNECT";
                bool is_ip = isIPHostnameStrip(urld);
                if (is_ssl && (!ismitmcandidate) && ((retchar = o.fg[filtergroup]->inBannedSSLSiteList(urld, false, is_ip, is_ssl)) != NULL))  	// blocked SSL site
                {
                    checkme.whatIsNaughty = o.language_list.getTranslation(520);  // banned site
                    message_no = 520;
                    checkme.whatIsNaughty += retchar;
                    checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                    checkme.isItNaughty = true;
                    checkme.whatIsNaughtyCategories = o.lm.l[o.fg[filtergroup]->banned_ssl_site_list]->lastcategory.toCharArray();
                }

                if (o.fg[filtergroup]->inExceptionSiteList(urld, true, is_ip, is_ssl)) 		// allowed site
                {
                    if (o.fg[0]->isOurWebserver(url))                    {
                        isourwebserver = true;
                    }                    else                    {
                        isexception = true;
                        exceptionreason = o.language_list.getTranslation(602);
                        message_no = 602;
                        // Exception site match.
                        exceptioncat = o.lm.l[o.fg[filtergroup]->exception_site_list]->lastcategory.toCharArray();
                    }
                }
                else if (o.fg[filtergroup]->inExceptionURLList(urld, true, is_ip, is_ssl))  	// allowed url
                {
                    isexception = true;
                    exceptionreason = o.language_list.getTranslation(603);
                    message_no = 603;
                    // Exception url match.
                    exceptioncat = o.lm.l[o.fg[filtergroup]->exception_url_list]->lastcategory.toCharArray();
                }
                else if ((rc = o.fg[filtergroup]->inExceptionRegExpURLList(urld)) > -1)                {
                    isexception = true;
                    // exception regular expression url match:
                    exceptionreason = o.language_list.getTranslation(609);
                    message_no = 609;
                    exceptionreason += o.fg[filtergroup]->exception_regexpurl_list_source[rc].toCharArray();
                    exceptioncat = o.lm.l[o.fg[filtergroup]->exception_regexpurl_list_ref[rc]]->category.toCharArray();
                }
                else if (!(*o.fg[filtergroup]).enable_local_list)                {
                    if (embededRefererChecks(&header, &urld, &url,filtergroup))   // referer exception
                    {
                        isexception = true;
                        exceptionreason = o.language_list.getTranslation(620);
                        message_no = 620;
                    }
                }


            }
            // if bannedregexwithblanketblock and exception check nevertheless
            if ((*o.fg[filtergroup]).enable_regex_grey && isexception && (!(isbypass || isbanneduser || isbannedip )))            {
                requestChecks(&header, &checkme, &urld, &url, &clientip, &clientuser, filtergroup, isbanneduser, isbannedip, room);
                // Debug deny code //
                // syslog(LOG_ERR, "code: %d", checkme.message_no); //
                if (checkme.message_no == 503 || checkme.message_no == 508 )                {
                    isexception = false;
                    message_no = checkme.message_no;
                }
            }

//
// End of main exception checking
//

#ifdef DGDEBUG
            std::cout << dbgPeerPort << " -extracted url:" << urld << std::endl;
#endif

            // don't run willScanRequest if content scanning is disabled, or on exceptions if contentscanexceptions is off,
            // or on SSL (CONNECT) requests, or on HEAD requests, or if in AV bypass mode
            String reqtype(header.requestType());
            isconnect = reqtype[0] == 'C';
            ishead = reqtype[0] == 'H';


            // Query request and response scanners to see which is interested in scanning data for this request
            // TODO - Should probably block if willScanRequest returns error
            bool multipart = false;
            if (!isbannedip && !isbanneduser && !isconnect && !ishead
                    && (o.fg[filtergroup]->disable_content_scan != 1)
                    && !(isexception && !o.content_scan_exceptions))
            {
                for (std::deque<Plugin *>::iterator i = o.csplugins_begin; i != o.csplugins_end; ++i)
                {
                    int csrc = ((CSPlugin*)(*i))->willScanRequest(header.getUrl(), clientuser.c_str(), filtergroup,
                               clientip.c_str(), false, false, isexception, isbypass);
                    if (csrc > 0)
                        responsescanners.push_back((CSPlugin*)(*i));
                    else if (csrc < 0)
                        syslog(LOG_ERR, "willScanRequest returned error: %d", csrc);
                }
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -Content scanners interested in response data: " << responsescanners.size() << std::endl;
#endif

                // Only query scanners regarding outgoing data if we are actually sending data in the request
                if (header.contentLength() > 0)
                {
                    // POST data log entry - fill in for single-part posts,
                    // and fill in overall "guess" for multi-part posts;
                    // latter will be overwritten with more detail about
                    // individual parts, if part-by-part filtering occurs.
                    String mtype(header.getContentType());
                    postparts.push_back(postinfo());
                    postparts.back().mimetype.assign(mtype);
                    postparts.back().size = header.contentLength();

                    if (mtype == "application/x-www-form-urlencoded" || (multipart = (mtype == "multipart/form-data")))
                    {
                        // Don't bother if it's a single part POST and is above max_content_ramcache_scan_size
                        if (!multipart && header.contentLength() > o.max_content_ramcache_scan_size)
                        {
#ifdef DGDEBUG
                            std::cout << dbgPeerPort << " -Not running willScanRequest for POST data: single-part POST with content length above size limit" << std::endl;
#endif
                        }
                        else
                        {
                            for (std::deque<Plugin *>::iterator i = o.csplugins_begin; i != o.csplugins_end; ++i)
                            {
                                int csrc = ((CSPlugin*)(*i))->willScanRequest(header.getUrl(), clientuser.c_str(), filtergroup,
                                           clientip.c_str(), true, !multipart, isexception, isbypass);
                                if (csrc > 0)
                                    requestscanners.push_back((CSPlugin*)(*i));
                                else if (csrc < 0)
                                    syslog(LOG_ERR, "willScanRequest returned error: %d", csrc);
                            }
                        }
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -Content scanners interested in request data: " << requestscanners.size() << std::endl;
#endif
                    }
                }
            }

            if (((isexception || iscookiebypass || isvirusbypass)
                    // don't filter exception and local web server
                    // Cookie bypass so don't need to add cookie so just CONNECT (unless should content scan)
                    && !isbannedip	 // bad users pc
                    && !isbanneduser	 // bad user
                    && requestscanners.empty() && responsescanners.empty())  // doesn't need content scanning
                    // bad people still need to be able to access the banned page
                    || isourwebserver)
            {
                proxysock.readyForOutput(o.proxy_timeout);  // exception on timeout or error
                header.out(&peerconn, &proxysock, __DGHEADER_SENDALL, true);  // send proxy the request
                docheader.in(&proxysock, persistOutgoing);
                persistProxy = docheader.isPersistent();
                persistPeer  = persistOutgoing && docheader.wasPersistent();
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -persistPeer: " << persistPeer << std::endl;
#endif
                docheader.out(NULL, &peerconn, __DGHEADER_SENDALL);
                // only open a two-way tunnel on CONNECT if the return code indicates success
                if (!(docheader.returnCode() == 200))                {
                    isconnect = false;
                }

                if (isconnect)                {                    persistProxy = false;                    persistOutgoing = false;                    persistPeer = false;                }

                try                {
                    fdt.reset();  // make a tunnel object
                    // tunnel from client to proxy and back
                    // two-way if SSL
                    fdt.tunnel(proxysock, peerconn, isconnect, docheader.contentLength(), true);  // not expected to exception
                    docsize = fdt.throughput;
                    if (!isourwebserver)  	// don't log requests to the web server
                    {
                        String rtype(header.requestType());
                        doLog(clientuser, clientip, logurl, header.port, exceptionreason, rtype, docsize, (exceptioncat.length() ? &exceptioncat : NULL), false, 0, isexception,
                              false, &thestart, cachehit, ((!isconnect && persistPeer) ? docheader.returnCode() : 200),
                              mimetype, wasinfected, wasscanned, 0, filtergroup, &header, message_no);
                    }
                    if (!persistProxy)
                        proxysock.close();  // close connection to proxy
                }
                catch (std::exception & e)                {
                }

                if (persistPeer)
                    continue;

                break;
            }

            if ((o.max_ips > 0) && (!gotIPs(clientip)))            {
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -no client IP slots left" << std::endl;
#endif
                checkme.isItNaughty = true;
                //checkme.whatIsNaughty = "IP limit exceeded.  There is a ";
                checkme.message_no = 10;
                checkme.whatIsNaughty = o.language_list.getTranslation(10);
                checkme.whatIsNaughty += String(o.max_ips).toCharArray();
                //checkme.whatIsNaughty += " IP limit set.";
                checkme.whatIsNaughty += o.language_list.getTranslation(11);
                checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                //checkme.whatIsNaughtyCategories = "IP Limit";
                checkme.whatIsNaughtyCategories = o.language_list.getTranslation(71);
            }

            // URL regexp search and redirect
            if (!is_ssl) urlredirect = header.urlRedirectRegExp(filtergroup);
            if (urlredirect)            {
                url = header.redirecturl();
#ifdef DGDEBUG
                std::cout<<"urlRedirectRegExp told us to redirect client to \"" << url << std::endl;
#endif
                proxysock.close();
                String writestring("HTTP/1.0 302 Redirect\nLocation: ");
                writestring += url ;
                writestring += "\n\n";
                peerconn.writeString(writestring.toCharArray());
                break;
            }

            if (!is_ssl) headeradded = header.isHeaderAdded(filtergroup);

            // URL regexp search and replace
            urlmodified = header.urlRegExp(filtergroup);
            if (urlmodified)            {
                url = header.getUrl();
                urld = header.decode(url);
                urldomain = url.getHostname();

                // if the user wants, re-check the exception site, URL and regex lists after modification.
                // this allows you to, for example, force safe search on Google URLs, then flag the
                // request as an exception, to prevent questionable language in returned site summaries
                // from blocking the entire request.
                // this could be achieved with exception phrases (which are, of course, always checked
                // after the URL) too, but there are cases for both, and flexibility is good.
                if (o.recheck_replaced_urls && !(isbanneduser || isbannedip))                {
                    //bool is_ssl = header.requestType() == "CONNECT";
                    bool is_ip = isIPHostnameStrip(urld);
                    if (o.fg[filtergroup]->inExceptionSiteList(urld, true, is_ip, is_ssl))  	// allowed site
                    {
                        if (o.fg[0]->isOurWebserver(url))                        {
                            isourwebserver = true;
                        }                        else                        {
                            isexception = true;
                            exceptionreason = o.language_list.getTranslation(602);
                            message_no = 602;
                            // Exception site match.
                            exceptioncat = o.lm.l[o.fg[filtergroup]->exception_site_list]->lastcategory.toCharArray();
                        }
                    }
                    else if (o.fg[filtergroup]->inExceptionURLList(urld, true, is_ip, is_ssl))  	// allowed url
                    {
                        isexception = true;
                        exceptionreason = o.language_list.getTranslation(603);
                        message_no = 603;
                        // Exception url match.
                        exceptioncat = o.lm.l[o.fg[filtergroup]->exception_url_list]->lastcategory.toCharArray();
                    }
                    else if ((rc = o.fg[filtergroup]->inExceptionRegExpURLList(urld)) > -1)                    {
                        isexception = true;
                        // exception regular expression url match:
                        exceptionreason = o.language_list.getTranslation(609);
                        message_no = 609;
                        exceptionreason += o.fg[filtergroup]->exception_regexpurl_list_source[rc].toCharArray();
                        exceptioncat = o.lm.l[o.fg[filtergroup]->exception_regexpurl_list_ref[rc]]->category.toCharArray();
                    }
                    // don't filter exception and local web server
                    if ((isexception
                            // even after regex URL replacement, we still don't want banned IPs/users viewing exception sites
                            && !isbannedip	 // bad users pc
                            && !isbanneduser	 // bad user
                            && requestscanners.empty() && responsescanners.empty())
                            || isourwebserver)
                    {
                        proxysock.readyForOutput(o.proxy_timeout);  // exception on timeout or error
                        header.out(&peerconn, &proxysock, __DGHEADER_SENDALL, true);  // send proxy the request
                        docheader.in(&proxysock, persistOutgoing);
                        persistProxy = docheader.isPersistent();
                        persistPeer  = persistOutgoing && docheader.wasPersistent();
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -persistPeer: " << persistPeer << std::endl;
#endif
                        docheader.out(NULL, &peerconn, __DGHEADER_SENDALL);

                        // only open a two-way tunnel on CONNECT if the return code indicates success
                        if (!(docheader.returnCode() == 200))                        {
                            isconnect = false;
                        }
                        if (isconnect)                        {                            persistProxy = false;                            persistOutgoing = false;                            persistPeer = false;                        }
                        try                        {
                            fdt.reset();  // make a tunnel object
                            // tunnel from client to proxy and back
                            // two-way if SSL
                            fdt.tunnel(proxysock, peerconn, isconnect, docheader.contentLength(), true);  // not expected to exception
                            docsize = fdt.throughput;
                            if (!isourwebserver)  	// don't log requests to the web server
                            {
                                String rtype(header.requestType());
                                doLog(clientuser, clientip, logurl, header.port, exceptionreason, rtype, docsize, (exceptioncat.length() ? &exceptioncat : NULL),
                                      false, 0, isexception, false, &thestart, cachehit, ((!isconnect && persistPeer) ? docheader.returnCode() : 200),
                                      mimetype, wasinfected, wasscanned, checkme.naughtiness, filtergroup, &header, message_no,
                                      // content wasn't modified, but URL was
                                      false, true, headermodified, headeradded);
                            }

                            if (!persistProxy)
                                proxysock.close();  // close connection to proxy
                        }
                        catch (std::exception & e)                        {
                        }

                        if (persistPeer)
                            continue;

                        break;
                    }
                }
            }

            // Outgoing header modifications
            headermodified = header.headerRegExp(filtergroup);

            // if o.content_scan_exceptions is on then exceptions have to
            // pass on until later for AV scanning too.
            // Bloody annoying feature that adds mess and complexity to the code
            if (isexception)            {
                checkme.isException = true;
                checkme.whatIsNaughtyLog = exceptionreason;
                checkme.whatIsNaughtyCategories = exceptioncat;
            }

            if (isconnect && !isbypass && !isexception)            {
                if (!authed)                {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -CONNECT: user not authed - getting response to see if it's auth required" << std::endl;
#endif
                    // send header to proxy
                    proxysock.readyForOutput(o.proxy_timeout);
                    header.out(NULL, &proxysock, __DGHEADER_SENDALL, true);

                    // get header from proxy
                    proxysock.checkForInput(o.exchange_timeout);
                    docheader.in(&proxysock, persistOutgoing);
                    persistProxy = docheader.isPersistent();
                    persistPeer  = persistOutgoing && docheader.wasPersistent();
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -persistPeer: " << persistPeer << std::endl;
#endif
                    wasrequested = true;

                    if (docheader.returnCode() != 200)
                    {
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -CONNECT: user not authed - doing standard filtering on auth required response" << std::endl;
#endif
                        isconnect = false;
                    }
                }
#ifdef DGDEBUG
                std::cout << dbgPeerPort << "isconnect=" << isconnect << " ismitmcandidate=" << ismitmcandidate << " only_mitm_ssl_grey=" << o.fg[filtergroup]->only_mitm_ssl_grey << std::endl;
#endif

                if (isconnect && ((!ismitmcandidate) || o.fg[filtergroup]->only_mitm_ssl_grey))                {
                    persistProxy = false;
                    persistPeer = false;
                    persistOutgoing = false;
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -CONNECT: user is authed/auth not required - attempting pre-emptive ban" << std::endl;
#endif
                    // if its a connect and we don't do filtering on it now then
                    // it will get tunneled and not filtered.  We can't tunnel later
                    // as its ssl so we can't see the return header etc
                    // So preemptive banning is forced on with ssl unfortunately.
                    // It is unlikely to cause many problems though.
                    requestChecks(&header, &checkme, &urld, &url, &clientip, &clientuser, filtergroup, isbanneduser, isbannedip, room);
                    message_no = checkme.message_no;
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -done checking" << std::endl;
#endif
                }
            }

            // Banned rewrite SSL denied page
            if ((is_ssl == true) && (checkme.isItNaughty == true) && (o.fg[filtergroup]->ssl_denied_rewrite == true))            {
                header.DenySSL(filtergroup);
                String rtype(header.requestType());
                doLog(clientuser, clientip, logurl, header.port, checkme.whatIsNaughtyLog, rtype, docsize, &checkme.whatIsNaughtyCategories, true, checkme.blocktype, isexception, false, &thestart,cachehit, (wasrequested ? docheader.returnCode() : 200), mimetype, wasinfected, wasscanned, checkme.naughtiness, filtergroup, &header, message_no, false, urlmodified, headermodified, headeradded);
                checkme.isItNaughty = false;
            }

            if (!checkme.isItNaughty && isconnect)            {
                // can't filter content of CONNECT
                if (!wasrequested)                {
                    proxysock.readyForOutput(o.proxy_timeout);  // exception on timeout or error
                    header.out(NULL, &proxysock, __DGHEADER_SENDALL, true);  // send proxy the request
                }                else                {
                    docheader.out(NULL, &peerconn, __DGHEADER_SENDALL);
                }
                try                {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -Opening tunnel for CONNECT" << std::endl;
#endif
                    fdt.reset();  // make a tunnel object
                    // tunnel from client to proxy and back - *true* two-way tunnel
                    fdt.tunnel(proxysock, peerconn, true);  // not expected to exception
                    docsize = fdt.throughput;
                    String rtype(header.requestType());
                    doLog(clientuser, clientip, logurl, header.port, exceptionreason, rtype, docsize, &checkme.whatIsNaughtyCategories, false,
                          0, isexception, false, &thestart,
                          cachehit, (wasrequested ? docheader.returnCode() : 200), mimetype, wasinfected,
                          wasscanned, checkme.naughtiness, filtergroup, &header, message_no, false, urlmodified, headermodified, headeradded);

                    if (!persistProxy)
                        proxysock.close();  // close connection to proxy
                }
                catch (std::exception & e)                {
                }

                if (persistPeer)
                    continue;

                break;
            }

            // check header sent to proxy - this is done before the send, so that pre-emptive banning
            // can be used for authenticated users. this gets around the problem of Squid fetching content
            // from sites when they're just going to get banned: not too big an issue in most cases, but
            // not good if blocking sites it would be illegal to retrieve, and allows web bugs/tracking
            // links not to be requested.
            if (authed && !isbypass && !isexception && !checkme.isItNaughty)            {
                requestChecks(&header, &checkme, &urld, &url, &clientip, &clientuser, filtergroup,
                              isbanneduser, isbannedip, room);
                message_no = checkme.message_no;
            }

            // TODO - This post code is too big
            // Filtering of POST data
            off_t cl = header.contentLength();
            if (authed && !checkme.isItNaughty && cl > 0)
            {
                // Check for POST upload size blocking, unless request is an exception
                // MIME type test is just an approximation, but probably good enough

                long max_upload_size;
                max_upload_size=(*o.fg[filtergroup]).max_upload_size;

#ifdef DGDEBUG
                std::cout << dbgPeerPort << " max upload size general: " << max_upload_size << " filtergroup " << filtergroup << ": " << (*o.fg[filtergroup]).max_upload_size << std::endl;

#endif
                if (!isbypass && !isexception
                        && ((max_upload_size >= 0) && (cl > max_upload_size))
                        && multipart)
                {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -Detected POST upload violation by Content-Length header - discarding rest of POST data..." << max_upload_size << std::endl;
#endif
                    header.discard(&peerconn);
                    checkme.whatIsNaughty = (*o.fg[filtergroup]).max_upload_size == 0 ? o.language_list.getTranslation(700) : o.language_list.getTranslation(701);
                    // Web upload is banned.
                    checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                    checkme.whatIsNaughtyCategories = "Web upload";
                    checkme.isItNaughty = true;
                    ispostblock = true;
                }
                else if (!requestscanners.empty())
                {
                    // POST scanning by content scanning plugins
                    if (multipart)
                    {
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -Filtering multi-part POST data" << std::endl;
#endif
                        // multi-part POST, possibly including file upload
                        // retrieve each part in turn and filter it on the fly

                        // network retrieval buffer
                        char buffer[2048];
                        size_t bytes_remaining = cl;

                        // determine boundary between MIME parts
                        // limit boundary to a sensible maximum to prevent DoS
                        String boundary("--");
                        boundary.append(header.getMIMEBoundary());
                        // include trailing "\r\n" or "--" in length
                        // later on, will also include leading "\r\n"
                        // need to make sure boundary fits in half our network buffer,
                        // or we won't be able to locate instances of it reliably
                        if ((boundary.length() + 2) == 0 || (boundary.length() + 2) > 1022)
                            throw postfilter_exception("Could not determine boundary for multi-part POST");

#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -Boundary: " << boundary << std::endl;
#endif

                        // Grab remaining data, including trailing boundary
                        // Split into parts and process each as we go
                        std::auto_ptr<BackedStore> part;
                        std::string rolling_buffer;
                        std::string trailer;
                        rolling_buffer.reserve(2048);
                        bool first = true;
                        bool last = false;
                        // Iterate over all parts.  Stop filtering after the first blocked part,
                        // for performance, but keep processing so that we can store all parts
                        // if necessary.
                        while (bytes_remaining > 0 && !last /*&& !checkme.isItNaughty*/)
                        {
                            // Grab the next chunk of data
                            int bytes_this_time = bytes_remaining > (2048 - rolling_buffer.length())
                                                  ? (2048 - rolling_buffer.length()) : bytes_remaining;
                            int rc = peerconn.readFromSocketn(buffer, bytes_this_time, 0, 10);
                            if (rc < bytes_this_time)
                                throw postfilter_exception("Could not retrieve POST data from browser");

                            // Put up to (chunk size * 2) in rolling buffer
                            rolling_buffer.append(buffer, bytes_this_time);
                            bytes_remaining -= bytes_this_time;

                            bool foundb = false;
                            do
                            {
                                // Process data from left of buffer
                                std::string::size_type loc = rolling_buffer.find(boundary);
                                if ((loc == std::string::npos) || (rolling_buffer.length() - (loc + (boundary.length() + 2)) < 0))
                                {
                                    // Didn't contain the boundary, or wasn't long enough
                                    // to contain boundary plus trailer - append up to
                                    // the first half of the rolling buffer to the
                                    // current part, then discard it
                                    loc = 1024 < rolling_buffer.length() ? 1024 : rolling_buffer.length();
                                    foundb = false;
                                }
                                else
                                {
                                    // Contained the boundary - append data up to the
                                    // boundary, discard that data plus boundary
                                    foundb = true;
                                    // See what the two trailing bytes of the boundary are
                                    trailer.assign(rolling_buffer.substr(loc + boundary.length(), 2));
                                    if (trailer == "--")
                                        last = true;
                                    else if (trailer != "\r\n")
                                        throw postfilter_exception("Unrecognised multi-part POST boundary trailer");
                                }

                                // Store data from left-hand half of buffer
                                // Don't bother storing the preamble
                                if (!first)
                                {
                                    if (part.get() != NULL && part->append(rolling_buffer.substr(0, loc).c_str(), loc))
                                    {
                                        if (foundb)
                                        {
                                            // Determine where the headers end and the data begins
                                            part->finalise();
                                            const char *data = part->getData();
                                            size_t offset = 0;
                                            bool foundend = false;
                                            do
                                            {
                                                void *headend = memchr((void*)(data + offset), '\r', part->getLength() - offset);
                                                if (headend == NULL)
                                                    // not found
                                                    break;
                                                offset = (size_t) headend - (size_t)(data);
                                                if ((part->getLength() - offset) >= 4
                                                        && strncmp(data + offset, "\r\n\r\n", 4) == 0)
                                                {
                                                    // found
                                                    foundend = true;
                                                    break;
                                                }
                                                // not found, but keep looking
                                                ++offset;
                                            }
                                            while (offset < (ssize_t)(part->getLength() - 4));

                                            if (!foundend)
                                                throw postfilter_exception("End of POST data part headers not found");
#ifdef DGDEBUG
                                            std::cout << dbgPeerPort << " -POST data headers: " << std::string(data, offset) << std::endl;
#endif
                                            // Extract pertinent info from part's headers
                                            String mimetype;
                                            String disposition;
                                            size_t hdr_offset = 0;
                                            do
                                            {
                                                // Look for the end of the next header line in the section of the part
                                                // that we know consists of headers (plus the last '\r')
                                                void *headend = memchr((void*)(data + hdr_offset), '\r', (offset - hdr_offset) + 1);
                                                if (headend == NULL)
                                                    // not found
                                                    break;
                                                size_t new_hdr_offset = (size_t) headend - (size_t) (data);
                                                if ((new_hdr_offset - hdr_offset > 14)
                                                        && strncasecmp(data + hdr_offset + 9, "ype: ", 5) == 0)
                                                {
                                                    // found Content-Type
                                                    mimetype.assign(data + (hdr_offset + 14), new_hdr_offset - (hdr_offset + 14));
                                                }
                                                else if ((new_hdr_offset - hdr_offset > 21)
                                                         && strncasecmp(data + hdr_offset + 9, "isposition: ", 12) == 0)
                                                {
                                                    // found Content-Disposition
                                                    disposition.assign(data + (hdr_offset + 21), new_hdr_offset - (hdr_offset + 21));
                                                }
                                                // Restart from end of current header (also skip '\n')
                                                hdr_offset = new_hdr_offset + 2;
                                            }
                                            while (hdr_offset < offset);
#ifdef DGDEBUG
                                            std::cout << dbgPeerPort << " -POST part MIME type: " << mimetype << std::endl;
                                            std::cout << dbgPeerPort << " -POST part disposition: " << disposition << std::endl;
#endif
                                            // Put info about the part in the POST parts list, for logging
                                            if (mimetype.empty())
                                                mimetype.assign("text/plain");
                                            postparts.push_back(postinfo());
                                            postparts.back().mimetype.assign(mimetype);
                                            std::string::size_type start = disposition.find("filename=");
                                            if (start != std::string::npos)
                                            {
                                                start += 9;
                                                char endchar = ';';
                                                if (disposition[start] == '"')
                                                {
                                                    endchar = '"';
                                                    ++start;
                                                }
                                                std::string::size_type end = disposition.find(endchar, start);
                                                if (end != std::string::npos)
                                                    postparts.back().filename = disposition.substr(start, end - start);
                                                else
                                                    postparts.back().filename = disposition.substr(start);
                                            }
                                            // Don't include "\r\n\r\n" in part's body data
                                            offset += 4;
                                            postparts.back().size = part->getLength();
                                            postparts.back().bodyoffset = offset;

                                            // Pre-emptively store the data part if storage is enabled.
                                            // If, when we get to the end of the filtering, the request
                                            // is not blocked/marked for storage, all parts will then
                                            // be deleted.  We need all parts to give decent context.
                                            if (!o.blocked_content_store.empty())
                                            {
                                                postparts.back().storedname = part->store(o.blocked_content_store.c_str());
#ifdef DGDEBUG
                                                std::cout << dbgPeerPort << " -Pre-emptively stored POST data part: " << postparts.back().storedname << std::endl;
#endif
                                            }

                                            // Run part through interested request scanning plugins
                                            if (!checkme.isItNaughty)
                                            {
                                                for (std::deque<CSPlugin *>::iterator i = requestscanners.begin(); i != requestscanners.end(); ++i)
                                                {
                                                    int csrc = (*i)->willScanData(header.getUrl(), clientuser.c_str(), filtergroup, clientip.c_str(),
                                                                                  true, false, isexception, isbypass, disposition, mimetype, part->getLength() - offset);
#ifdef DGDEBUG
                                                    std::cerr << dbgPeerPort << " -willScanData returned: " << csrc << std::endl;
#endif
                                                    if (csrc > 0)
                                                    {
                                                        csrc = (*i)->scanMemory(&header, NULL, clientuser.c_str(), filtergroup, clientip.c_str(),
                                                                                data + offset, part->getLength() - offset, &checkme,
                                                                                &disposition, &mimetype);
                                                        if (csrc != DGCS_CLEAN && csrc != DGCS_WARNING)
                                                        {
                                                            checkme.blocktype = 1;
                                                            postparts.back().blocked = true;
                                                            // Don't delete part (yet) if in stealth mode - need to send the data upstream
                                                            if (o.fg[filtergroup]->reporting_level != -1)
                                                                part.reset();
                                                        }
                                                        if (csrc == DGCS_BLOCKED)                                                        {
                                                            // Send part upstream anyway if in stealth mode
                                                            if (o.fg[filtergroup]->reporting_level != -1)
                                                                break;
                                                        }
                                                        else if (csrc == DGCS_INFECTED)                                                        {
                                                            wasinfected = true;
                                                            // Send part upstream anyway if in stealth mode
                                                            if (o.fg[filtergroup]->reporting_level != -1)
                                                                break;
                                                        }
                                                        //if its not clean / we errored then treat it as infected
                                                        else if (csrc != DGCS_CLEAN && csrc != DGCS_WARNING)                                                        {
                                                            if (csrc < 0)                                                            {
                                                                syslog(LOG_ERR, "Return code from content scanner: %d", csrc);
                                                            }
                                                            else                                                            {
                                                                syslog(LOG_ERR, "scanFile/Memory returned error: %d", csrc);
                                                            }
                                                            //TODO: have proper error checking/reporting here?
                                                            //at the very least, integrate with the translation system.
                                                            //checkme.whatIsNaughty = "WARNING: Could not perform content scan!";
                                                            checkme.message_no = 1203;
                                                            checkme.whatIsNaughty = o.language_list.getTranslation(1203);
                                                            checkme.whatIsNaughtyLog = (*i)->getLastMessage().toCharArray();
                                                            //checkme.whatIsNaughtyCategories = "Content scanning";
                                                            checkme.whatIsNaughtyCategories = o.language_list.getTranslation(72);
                                                            checkme.isItNaughty = true;
                                                            checkme.isException = false;
                                                            scanerror = true;
                                                            break;
                                                        }
                                                    }
                                                    else if (csrc < 0)
                                                        // TODO - Should probably block here
                                                        syslog(LOG_ERR, "willScanData returned error: %d", csrc);
                                                }
                                            }
                                            // Send whole part upstream
                                            if (!checkme.isItNaughty || o.fg[filtergroup]->reporting_level == -1)
                                                proxysock.writeToSockete(data, part->getLength(), 0, 20);
                                        }
                                    }
                                    else
                                    {
                                        // Data could not be appended to the buffered POST part
                                        // - length must have exceeded maxcontentfilecachescansize,
                                        // so send the part directly upstream instead
                                        if (part.get() != NULL)
                                        {
#ifdef DGDEBUG
                                            std::cout << dbgPeerPort << " -POST data part too large, sending upstream" << std::endl;
#endif
                                            // Send what we've buffered so far, then delete the buffer
                                            part->finalise();
                                            proxysock.writeToSockete(part->getData(), part->getLength(), 0, 20);
                                            part.reset();
                                        }
                                        // Send current chunk upstream directly
                                        proxysock.writeToSockete(rolling_buffer.substr(0, loc).c_str(), loc, 0, 20);
                                    }
                                    if (foundb)
                                    {
                                        if (!checkme.isItNaughty || o.fg[filtergroup]->reporting_level == -1)
                                        {
                                            // Regardless of whether we were buffering or streaming, send the
                                            // boundary and trailers upstream if this was the last chunk of a part
                                            proxysock.writeToSockete(boundary.c_str(), boundary.length(), 0, 10);
                                            proxysock.writeToSockete(trailer.c_str(), trailer.length(), 0, 10);
                                            // Include final CRLF (after the trailer) after last boundary
                                            if (last)
                                                proxysock.writeToSockete("\r\n", 2, 0, 10);
                                        }
                                        part.reset(new BackedStore(o.max_content_ramcache_scan_size, o.max_content_filecache_scan_size));
                                    }
                                }

                                // If we found the boundary, include boundary size
                                // in the length of data we will discard
                                if (foundb)
                                {
                                    loc += boundary.length() + 2;
                                    if (first)
                                    {
                                        // We just past the preamble/first boundary
                                        // Send request headers and first boundary upstream
#ifdef DGDEBUG
                                        std::cout << dbgPeerPort << " -Preamble/first boundary passed; sending headers & first boundary upstream" << std::endl;
#endif
                                        if (!wasrequested && (!checkme.isItNaughty || o.fg[filtergroup]->reporting_level == -1))
                                        {
                                            proxysock.readyForOutput(o.proxy_timeout);
                                            // sent *without* POST data, so cannot retrieve headers yet
                                            header.out(NULL, &proxysock, __DGHEADER_SENDALL, true);
                                            wasrequested = true;
                                            proxysock.writeToSockete(boundary.c_str(), boundary.length(), 0, 10);
                                            proxysock.writeToSockete(trailer.c_str(), trailer.length(), 0, 10);
                                        }
                                        first = false;
                                        // Clear out dummy log data so it can be filled in
                                        // with info about each POST part individually
                                        postparts.clear();
                                        // For all boundaries after the first, include the leading CRLF
                                        boundary.insert(0, "\r\n");
                                        // Create BackedStore for first data part
                                        part.reset(new BackedStore(o.max_content_ramcache_scan_size, o.max_content_filecache_scan_size));
                                    }
                                }
                                rolling_buffer.erase(0, loc);
                            }
                            while (foundb /*&& !checkme.isItNaughty*/);
                        } // while bytes_remaining > 0 && !last /* && not blocked */

                        // If the request is not blocked or storage has not been requested,
                        // delete all the (possibly) pre-emptively stored data parts
                        if (!o.blocked_content_store.empty() && (!checkme.isItNaughty || !checkme.store))
                        {
#ifdef DGDEBUG
                            std::cout << dbgPeerPort << " -Request was not blocked/marked for storage. Deleting data parts:" << std::endl;
#endif
                            for (std::list<postinfo>::iterator i = postparts.begin(); i != postparts.end(); ++i)
                            {
                                if (i->storedname.empty())
                                    continue;
#ifdef DGDEBUG
                                std::cout << dbgPeerPort << " -Part " << i->storedname << std::endl;
#endif
                                unlink(i->storedname.c_str());
                                i->storedname.clear();
                            }
#ifdef DGDEBUG
                            std::cout << dbgPeerPort << " -All parts deleted" << std::endl;
#endif
                        }

                        if (!checkme.isItNaughty)
                        {
                            // Were we still within a part when the data came to an end?
                            // Did we not find a correctly-formatted last part boundary?
                            // Was there data (other than a CRLF) remaining after the final boundary?
                            if (rolling_buffer.length() > 2 || !last || bytes_remaining > 2)
                            {
                                std::ostringstream ss;
                                ss << "Last part of multi-part POST was not correctly terminated.  Part length: ";
                                ss << part->getLength() << ", bytes remaining: " << bytes_remaining << ", last part found: " << last;
                                throw postfilter_exception(ss.str().c_str());
                            }
                            // get header from proxy
                            // wasrequested will have been set to true (we have had to send out
                            // the request headers & POST data by the time we get here), so none
                            // of the code below here will do this for us.
#ifdef DGDEBUG
                            std::cout << dbgPeerPort << " -All parts sent upstream; retrieving response headers" << std::endl;
#endif
                            proxysock.checkForInput(120);
                            docheader.in(&proxysock, persistOutgoing);
                            persistProxy = docheader.isPersistent();
                            persistPeer  = persistOutgoing && docheader.wasPersistent();

#ifdef DGDEBUG
                            std::cout << dbgPeerPort << " -persistPeer: " << persistPeer << std::endl;
#endif

                        }
                        else
                        {
                            // Was blocked - discard rest of POST data before we show the block page
#ifdef DGDEBUG
                            std::cout << dbgPeerPort << " -POST data part blocked; discarding remaining POST data" << std::endl;
#endif
                            // Send rest of data upstream anyway if in stealth mode
                            if (o.fg[filtergroup]->reporting_level == -1)
                            {
                                proxysock.writeToSockete(rolling_buffer.c_str(), rolling_buffer.length(), 0, 10);
                                fdt.reset();
                                fdt.tunnel(peerconn, proxysock, false, bytes_remaining, false);
                                // Also retrieve response headers, if wasrequested was set to true,
                                // because nothing else will do so later on
                                if (wasrequested)
                                {
                                    docheader.in(&proxysock, persistOutgoing);
                                    persistProxy = docheader.isPersistent();
                                    persistPeer  = persistOutgoing && docheader.wasPersistent();
#ifdef DGDEBUG
                                    std::cout << dbgPeerPort << " -persistPeer: " << persistPeer << std::endl;
#endif

                                }
                            }
                            else
                                header.discard(&peerconn, bytes_remaining);
                        }

                    }
                    else // if (mtype == "application/x-www-form-urlencoded")
                    {
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -Filtering single-part POST data" << std::endl;
#endif
                        // single-part POST (plain-text form data)
                        // we know the size for the part has already been checked by this point
                        // TODO Change this to use a BackedStore for consistency, and so that we
                        // don't have to have cut-and-pasted code in the blocked content storage
                        // implementation?  Should possibly make this a loop around a more
                        // light-weight socket read function, as even if we won't get data into the
                        // BackedStore in a zero-copy fashion, there is no reason to have *too*
                        // much copied data sat around in RAM.
                        // Also a "reserve()"-alike for BackedStore wouldn't go amiss, as we know
                        // the data size in advance.
                        char buffer[cl];
                        int rc = peerconn.readFromSocketn(buffer, cl, 0, 10);

                        if (rc < 0)
                            throw postfilter_exception("Could not retrieve POST data from browser");

                        // Set the POST data buffer on the request, so that it
                        // does not block indefinitely trying to tunnel data that
                        // the browser has already sent
                        header.setPostData(buffer, cl);

                        // data looks like "name=value+1&name2=value+2".
                        // parse the text to remove variable names and pad with
                        // spaces at beginning & end.
                        String result(" ");
                        bool inname = true;
                        for (off_t i = 1; i < cl; ++i)
                        {
                            if (inname)
                            {
                                if (buffer[i] == '=')
                                    inname = false;
                            }
                            else
                            {
                                if (buffer[i] == '&')
                                {
                                    inname = true;
                                    result.append(" ");
                                }
                                else
                                    result.append(1, buffer[i]);
                            }
                        }
                        result.append(" ");

                        // turn '+' back into ' '
                        result.replaceall("+", " ");

                        // decode %xx
                        result = HTTPHeader::decode(result, true);

                        // Run the result through request scanners which are happy to deal with reconstituted data
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -Form data: " << result.c_str() << std::endl;
#endif
                        for (std::deque<CSPlugin *>::iterator i = requestscanners.begin(); i != requestscanners.end(); ++i)
                        {
                            int csrc = (*i)->willScanData(header.getUrl(), clientuser.c_str(), filtergroup, clientip.c_str(),
                                                          true, true, isexception, isbypass, "", "text/plain", result.length());
#ifdef DGDEBUG
                            std::cerr << dbgPeerPort << " -willScanData returned: " << csrc << std::endl;
#endif
                            if (csrc > 0)
                            {
                                String mimetype("text/plain");
                                csrc = (*i)->scanMemory(&header, NULL, clientuser.c_str(), filtergroup, clientip.c_str(),
                                                        result.c_str(), result.length(), &checkme, NULL, &mimetype);
                                if (csrc != DGCS_CLEAN && csrc != DGCS_WARNING)
                                {
                                    checkme.blocktype = 1;
                                    postparts.back().blocked = true;
                                    if (checkme.store && !o.blocked_content_store.empty())
                                    {
                                        // Write original encoded buffer to disk
                                        std::ostringstream timedprefix;
                                        timedprefix << o.blocked_content_store << '-' << time(NULL) << '-' << std::flush;
                                        std::string pfx(timedprefix.str());
                                        char storedname[pfx.length() + 7];
                                        strncpy(storedname, pfx.c_str(), pfx.length());
                                        strncpy(storedname + pfx.length(), "XXXXXX", 6);
                                        storedname[pfx.length() + 6] = '\0';
#ifdef DGDEBUG
                                        std::cout << dbgPeerPort << " -Single-part POST: storedname template: " << storedname << std::endl;
#endif
                                        int storefd;
                                        if ((storefd = mkstemp(storedname)) < 0)
                                        {
                                            std::ostringstream ss;
                                            ss << "Could not create file for single-part POST data: " << strerror(errno);
                                            throw std::runtime_error(ss.str().c_str());
                                        }
#ifdef DGDEBUG
                                        std::cout << dbgPeerPort << " -Single-part POST: storedname: " << storedname << std::endl;
#endif
                                        postparts.back().storedname = storedname;
                                        ssize_t bytes_written = 0;
                                        ssize_t rc = 0;
                                        do
                                        {
                                            rc = write(storefd, buffer + bytes_written, cl - bytes_written);
                                            if (rc > 0)
                                                bytes_written += rc;
                                        }
                                        while (bytes_written < cl && (rc > 0 || errno == EINTR));
                                        if (rc < 0 && errno != EINTR)
                                        {
                                            std::ostringstream ss;
                                            ss << "Could not write single-part POST data to file: " << strerror(errno);
                                            do
                                            {
                                                rc = close(storefd);
                                            }
                                            while (rc < 0 && errno == EINTR);
                                            throw std::runtime_error(ss.str().c_str());
                                        }
                                        do
                                        {
                                            rc = close(storefd);
                                        }
                                        while (rc < 0 && errno == EINTR);
                                    }
                                }
                                if (csrc == DGCS_BLOCKED)                                {
                                    break;
                                }
                                else if (csrc == DGCS_INFECTED)                                {
                                    wasinfected = true;
                                    break;
                                }
                                //if its not clean / we errored then treat it as infected
                                else if (csrc != DGCS_CLEAN && csrc != DGCS_WARNING)                                {
                                    if (csrc < 0)                                    {
                                        syslog(LOG_ERR, "Unknown return code from content scanner: %d", csrc);
                                    }
                                    else                                    {
                                        syslog(LOG_ERR, "scanFile/Memory returned error: %d", csrc);
                                    }
                                    //TODO: have proper error checking/reporting here?
                                    //at the very least, integrate with the translation system.
                                    //checkme.whatIsNaughty = "WARNING: Could not perform content scan!";
                                    checkme.message_no = 1203;
                                    checkme.whatIsNaughty = o.language_list.getTranslation(1203);
                                    checkme.whatIsNaughtyLog = (*i)->getLastMessage().toCharArray();
                                    checkme.whatIsNaughtyCategories = "Content scanning";
                                    //checkme.whatIsNaughtyCategories = "Content scanning";
                                    checkme.whatIsNaughtyCategories = o.language_list.getTranslation(72);
                                    checkme.isItNaughty = true;
                                    checkme.isException = false;
                                    scanerror = true;
                                    break;
                                }
                            }
                            else if (csrc < 0)
                                // TODO - Should probably block here
                                syslog(LOG_ERR, "willScanData returned error: %d", csrc);
                        }
                    }
                    // Cannot be other, unknown MIME type because MIME type
                    // is checked before CS plugins are queried (so plugin lists
                    // will be empty for other MIME types)
                }
            }
#ifdef DGDEBUG
            // Banning POST requests for unauthed users (when auth is enabled) could potentially prevent users from authenticating.
            else if (!authed)
                std::cout << dbgPeerPort << " -Skipping POST filtering because user is unauthed." << std::endl;
#endif

            if (!checkme.isItNaughty)            {
                // the request is ok, so we can	now pass it to the proxy, and check the returned header
                // temp char used in various places here
                char *i;

                // send header to proxy
                if (!wasrequested)                {
                    proxysock.readyForOutput(o.proxy_timeout);
                    header.out(&peerconn, &proxysock, __DGHEADER_SENDALL, true);

                    // get header from proxy
                    proxysock.checkForInput(o.exchange_timeout);
                    docheader.in(&proxysock, persistOutgoing);
                    persistProxy = docheader.isPersistent();
                    persistPeer  = persistOutgoing && docheader.wasPersistent();
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -persistPeer: " << persistPeer << std::endl;
#endif

                    wasrequested = true;  // so we know where we are later
                }

#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -got header from proxy" << std::endl;
                if (!persistProxy)
                    std::cout << dbgPeerPort << " -header says close, so not persisting" << std::endl;
#endif

                // if we're not careful, we can end up accidentally setting the bypass cookie twice.
                // because of the code flow, this second cookie ends up with timestamp 0, and is always disallowed.
                if (isbypass && !isvirusbypass && !iscookiebypass)                {
#ifdef DGDEBUG
                    std::cout<<"Setting GBYPASS cookie; bypasstimestamp = "<<bypasstimestamp<<std::endl;
#endif
                    String ud(urldomain);
                    if (ud.startsWith("www."))                    {
                        ud = ud.after("www.");
                    }

                    docheader.setCookie("GBYPASS", ud.toCharArray(), hashedCookie(&ud, o.fg[filtergroup]->cookie_magic.c_str(), &clientip, bypasstimestamp).toCharArray());

                    // redirect user to URL with GBYPASS parameter no longer appended
                    docheader.header[0] = "HTTP/1.0 302 Redirect";
                    String loc("Location: ");
                    loc += header.getUrl(true);
                    docheader.header.push_back(loc);
                    docheader.setContentLength(0);

                    persistOutgoing = false;
                    docheader.out(NULL, &peerconn, __DGHEADER_SENDALL);

                    if (!persistProxy)
                        proxysock.close();  // close connection to proxy

                    break;
                }

                // don't even bother scan testing if the content-length header indicates the file is larger than the maximum size we'll scan
                // - based on patch supplied by cahya (littlecahya@yahoo.de)
                // be careful: contentLength is signed, and max_content_filecache_scan_size is unsigned
                off_t cl = docheader.contentLength();
                if (!responsescanners.empty())                {
                    if (cl == 0)
                        responsescanners.clear();
                    else if ((cl > 0) && (cl > o.max_content_filecache_scan_size))
                        responsescanners.clear();
                }

                // now that we have the proxy's header too, we can make a better informed decision on whether or not to scan.
                // this used to be done before we'd grabbed the proxy's header, rendering exceptionvirusmimetypelist useless,
                // and exceptionvirusextensionlist less effective, because we didn't have a Content-Disposition header.
                if (!responsescanners.empty())
                {
#ifdef DGDEBUG
                    std::cerr << dbgPeerPort << " -Number of response CS plugins in candidate list: " << responsescanners.size() << std::endl;
#endif
                    //send header to plugin here needed
                    //also send user and group
#ifdef DGDEBUG
                    int j = 0;
#endif
                    std::deque<CSPlugin *> newplugins;
                    for (std::deque<CSPlugin *>::iterator i = responsescanners.begin(); i != responsescanners.end(); ++i)
                    {
                        int csrc = (*i)->willScanData(header.getUrl(), clientuser.c_str(), filtergroup, clientip.c_str(),
                                                      false, false, isexception, isbypass, docheader.disposition(), docheader.getContentType(), docheader.contentLength());
#ifdef DGDEBUG
                        std::cerr << dbgPeerPort << " -willScanData for plugin " << j << " returned: " << csrc << std::endl;
#endif
                        if (csrc > 0)
                            newplugins.push_back(*i);
                        else if (csrc < 0)
                            // TODO Should probably block on error
                            syslog(LOG_ERR, "willScanData returned error: %d", csrc);
#ifdef DGDEBUG
                        j++;
#endif
                    }

                    // Store only those plugins which responded positively to willScanData
                    responsescanners.swap(newplugins);
                }

                // no need to check bypass mode, exception mode, auth required headers, redirections, or banned ip/user (the latter get caught by requestChecks later)
                if (!isexception && !isbypass && !(isbannedip || isbanneduser) && !docheader.isRedirection() && !docheader.authRequired())
                {
                    bool download_exception = false;

                    // Check the exception file site and MIME type lists.
                    mimetype = docheader.getContentType().toCharArray();
                    if (o.fg[filtergroup]->inExceptionFileSiteList(urld))
                        download_exception = true;
                    else                    {
                        if (o.lm.l[o.fg[filtergroup]->exception_mimetype_list]->findInList(mimetype.c_str()))
                            download_exception = true;
                    }

                    // Perform banned MIME type matching
                    if (!download_exception)                    {
                        // If downloads are blanket blocked, block outright.
                        if (o.fg[filtergroup]->block_downloads)                        {
                            // did not match the exception list
                            checkme.whatIsNaughty = o.language_list.getTranslation(750);
                            // Blanket file download is active
                            checkme.whatIsNaughty += mimetype;
                            checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                            checkme.isItNaughty = true;
                            checkme.whatIsNaughtyCategories = "Blanket download block";
                        }
                        else if ((i = o.lm.l[o.fg[filtergroup]->banned_mimetype_list]->findInList(mimetype.c_str())) != NULL)                        {
                            // matched the banned list
                            checkme.whatIsNaughty = o.language_list.getTranslation(800);
                            // Banned MIME Type:
                            checkme.whatIsNaughty += i;
                            checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                            checkme.isItNaughty = true;
                            checkme.whatIsNaughtyCategories = "Banned MIME Type";
                        }

#ifdef DGDEBUG
                        std::cout << dbgPeerPort << mimetype.length() << std::endl;
                        std::cout << dbgPeerPort << " -:" << mimetype;
                        std::cout << dbgPeerPort << " -:" << std::endl;
#endif
                    }

                    // Perform extension matching - if not already matched the exception MIME or site lists
                    if (!download_exception)                    {
                        // Can't ban file extensions of URLs that just redirect
                        String tempurl(urld);
                        String tempdispos(docheader.disposition());
                        unsigned int elist, blist;
                        elist = o.fg[filtergroup]->exception_extension_list;
                        blist = o.fg[filtergroup]->banned_extension_list;
                        char* e = NULL;
                        char* b = NULL;
                        if (tempdispos.length() > 1)                        {
                            // dispos filename must take presidense
#ifdef DGDEBUG
                            std::cout << dbgPeerPort << " -Disposition filename:" << tempdispos << ":" << std::endl;
#endif
                            // The function expects a url so we have to
                            // generate a pseudo one.
                            tempdispos = "http://foo.bar/" + tempdispos;
                            e = o.fg[filtergroup]->inExtensionList(elist, tempdispos);
                            // Only need to check banned list if not blanket blocking
                            if ((e == NULL) && !(o.fg[filtergroup]->block_downloads))
                                b = o.fg[filtergroup]->inExtensionList(blist, tempdispos);
                        }                        else                        {
                            if (!tempurl.contains("?"))                            {
                                e = o.fg[filtergroup]->inExtensionList(elist, tempurl);
                                if ((e == NULL) && !(o.fg[filtergroup]->block_downloads))
                                    b = o.fg[filtergroup]->inExtensionList(blist, tempurl);
                            }
                            else if (String(mimetype.c_str()).contains("application/"))                            {
                                while (tempurl.endsWith("?"))                                {
                                    tempurl.chop();
                                }
                                while (tempurl.contains("/"))  	// no slash no url
                                {
                                    e = o.fg[filtergroup]->inExtensionList(elist, tempurl);
                                    if (e != NULL)
                                        break;
                                    if (!(o.fg[filtergroup]->block_downloads))
                                        b = o.fg[filtergroup]->inExtensionList(blist, tempurl);
                                    while (tempurl.contains("/") && !tempurl.endsWith("?"))                                    {
                                        tempurl.chop();
                                    }
                                    tempurl.chop();  // get rid of the ?
                                }
                            }
                        }

                        // If downloads are blanket blocked, block unless matched the exception list.
                        // If downloads are not blanket blocked, block if matched the banned list and not the exception list.
                        if (o.fg[filtergroup]->block_downloads && (e == NULL))                        {
                            // did not match the exception list
                            checkme.whatIsNaughty = o.language_list.getTranslation(751);
                            // Blanket file download is active
                            checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                            checkme.isItNaughty = true;
                            checkme.whatIsNaughtyCategories = "Blanket download block";
                        }
                        else if (!(o.fg[filtergroup]->block_downloads) && (e == NULL) && (b != NULL))                        {
                            // matched the banned list
                            checkme.whatIsNaughty = o.language_list.getTranslation(900);
                            // Banned extension:
                            checkme.whatIsNaughty += b;
                            checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                            checkme.isItNaughty = true;
                            checkme.whatIsNaughtyCategories = "Banned extension";
                        }
                        else if (e != NULL)                        {
                            // intention is to match either/or of the MIME & extension lists
                            // so if it gets this far, un-naughty it (may have been naughtied by the MIME type list)
                            checkme.isItNaughty = false;
                        }
                    }
                }

                // check header sent to proxy - this could be done before the send, but we
                // want to wait until after the MIME type & extension checks, because they may
                // act as a quicker rejection. also so as not to pre-emptively ban currently
                // un-authed users.
                if (!authed && !isbypass && !isexception && !checkme.isItNaughty && !docheader.authRequired())                {
                    requestChecks(&header, &checkme, &urld, &url, &clientip, &clientuser, filtergroup,
                                  isbanneduser, isbannedip, room);
                }

                // check body from proxy
                // can't do content filtering on HEAD or redirections (no content)
                // actually, redirections CAN have content
                if (!checkme.isItNaughty && (cl != 0) && !ishead)                {
                    if (((docheader.isContentType("text") || docheader.isContentType("-")) && !isexception) || !responsescanners.empty())                    {
                        // don't search the cache if scan_clean_cache disabled & runav true (won't have been cached)
                        // also don't search cache for auth required headers (same reason)

                        // checkme: does not searching the cache if scan_clean_cache is disabled break the fancy DM's bypass stuff?
                        // probably, since it uses a "magic" status code in the cache; easier than coding yet another hash type.

                        if (o.url_cache_number > 0 && (o.scan_clean_cache || responsescanners.empty()) && !docheader.authRequired())                        {
                            if (wasClean(header, urld, filtergroup))                            {
                                wasclean = true;
                                cachehit = true;
                                responsescanners.clear();
#ifdef DGDEBUG
                                std::cout << dbgPeerPort << " -url was clean skipping content and AV checking" << std::endl;
#endif
                            }
                        }
                        // despite the debug note above, we do still go through contentFilter for cached non-exception HTML,
                        // as content replacement rules need to be applied.
                        waschecked = true;
                        if (!responsescanners.empty())                        {
#ifdef DGDEBUG
                            std::cout << dbgPeerPort << " -Filtering with expectation of a possible csmessage" << std::endl;
#endif
                            String csmessage;
                            contentFilter(&docheader, &header, &docbody, &proxysock, &peerconn, &headersent, &pausedtoobig,
                                          &docsize, &checkme, wasclean, filtergroup, responsescanners, &clientuser, &clientip,
                                          &wasinfected, &wasscanned, isbypass, urld, urldomain, &scanerror, contentmodified, &csmessage);
                            if (csmessage.length() > 0)                            {
#ifdef DGDEBUG
                                std::cout << dbgPeerPort << " -csmessage found: " << csmessage << std::endl;
#endif
                                exceptionreason = csmessage.toCharArray();
                            }
                        }                        else                        {
                            contentFilter(&docheader, &header, &docbody, &proxysock, &peerconn, &headersent, &pausedtoobig,
                                          &docsize, &checkme, wasclean, filtergroup, responsescanners, &clientuser, &clientip,
                                          &wasinfected, &wasscanned, isbypass, urld, urldomain, &scanerror, contentmodified, NULL);
                        }
                    }
                }
            }

            if (!isexception && checkme.isException)            {
                isexception = true;
                exceptionreason = checkme.whatIsNaughtyLog;
            }

            if (o.url_cache_number > 0)            {
                // add to cache if: wasn't already there, wasn't naughty, wasn't allowed by bypass/soft block, was text,
                // was virus scanned and scan_clean_cache is enabled, was a GET request,
                // and response was not a set of auth required headers (we haven't checked
                // the actual content, just the proxy's auth error page!).
                // also don't add "not modified" responses to the cache - if someone adds
                // an entry and does a soft restart, we don't want the site to end up in
                // the clean cache because someone who's already been to it hits refresh.
                if (!wasclean && !checkme.isItNaughty && !isbypass
                        && (docheader.isContentType("text") || (wasscanned && o.scan_clean_cache))
                        && (header.requestType() == "GET") && (docheader.returnCode() == 200)
                        && urld.length() < 2000)
                {
                    addToClean(urld, filtergroup);
                }
            }

            // then we deny. previously, this checked the isbypass flag too; now, since bypass requests only undergo the same checking
            // as exceptions, it needn't. and in fact it mustn't, if bypass requests are to be virus scanned/blocked in the same manner as exceptions.
            // make sure we keep track of whether or not logging has been performed, as we may be in stealth mode and don't want to double log.
            bool logged = false;
            if (checkme.isItNaughty)            {
                String rtype(header.requestType());
#ifdef DGDEBUG
                std::cout<<"Category: "<<checkme.whatIsNaughtyCategories<<std::endl;
#endif
                logged = true;
                doLog(clientuser, clientip, logurl, header.port, checkme.whatIsNaughtyLog,
                      rtype, docsize, &checkme.whatIsNaughtyCategories, true, checkme.blocktype, false, false, &thestart,
                      cachehit, 403, mimetype, wasinfected, wasscanned, checkme.naughtiness, filtergroup,
                      &header, message_no, contentmodified, urlmodified, headermodified, headeradded);
                if (denyAccess(&peerconn, &proxysock, &header, &docheader, &logurl, &checkme, &clientuser,&clientip, filtergroup, ispostblock, headersent, wasinfected, scanerror))
                {
                    return 0;  // not stealth mode
                }

                // if get here in stealth mode
            }

            if (!wasrequested)            {
                proxysock.readyForOutput(o.proxy_timeout);  // exceptions on error/timeout
                header.out(&peerconn, &proxysock, __DGHEADER_SENDALL, true);  // exceptions on error/timeout
                proxysock.checkForInput(o.exchange_timeout);  // exceptions on error/timeout
                docheader.in(&proxysock, persistOutgoing);  // get reply header from proxy
                persistProxy = docheader.isPersistent();
                persistPeer  = persistOutgoing && docheader.wasPersistent();
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -persistPeer: " << persistPeer << std::endl;
#endif
            }

            //TODO: need to change connection: close if there is plugin involved.
#ifdef DGDEBUG
            std::cout << dbgPeerPort << " -sending header to client" << std::endl;
#endif
            peerconn.readyForOutput(o.proxy_timeout);  // exceptions on error/timeout
            if (headersent == 1)            {
                docheader.out(NULL, &peerconn, __DGHEADER_SENDREST);  // send rest of header to client
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -sent rest header to client" << std::endl;
#endif
            }
            else if (headersent == 0)            {
                docheader.out(NULL, &peerconn, __DGHEADER_SENDALL);  // send header to client
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -sent all header to client" << std::endl;
#endif
            }

            if (waschecked)            {
                if (!docheader.authRequired() && !pausedtoobig)                {
                    String rtype(header.requestType());
                    if (!logged)                    {
                        doLog(clientuser, clientip, logurl, header.port, exceptionreason,
                              rtype, docsize, &checkme.whatIsNaughtyCategories, false, 0, isexception,
                              docheader.isContentType("text"), &thestart, cachehit, docheader.returnCode(), mimetype,
                              wasinfected, wasscanned, checkme.naughtiness, filtergroup, &header, message_no,
                              contentmodified, urlmodified, headermodified, headeradded);
                    }
                }

                peerconn.readyForOutput(o.proxy_timeout);  // check for error/timeout needed

                // it must be clean if we got here
                if (docbody.dontsendbody && docbody.tempfilefd > -1)                {
                    // must have been a 'fancy'
                    // download manager so we need to send a special link which
                    // will get recognised and cause DG to send the temp file to
                    // the browser.  The link will be the original URL with some
                    // magic appended to it like the bypass system.

                    // format is:
                    // GSBYPASS=hash(ip+url+tempfilename+mime+disposition+secret)
                    // &N=tempfilename&M=mimetype&D=dispos

                    String ip(clientip);
                    String tempfilename(docbody.tempfilepath.after("/tf"));
                    String tempfilemime(docheader.getContentType());
                    String tempfiledis(miniURLEncode(docheader.disposition().toCharArray()).c_str());
                    String secret(o.fg[filtergroup]->magic.c_str());
                    String magic(ip + url + tempfilename + tempfilemime + tempfiledis + secret);
                    String hashed(magic.md5());
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -sending magic link to client: " << ip << " " << url << " " << tempfilename << " " << tempfilemime << " " << tempfiledis << " " << secret << " " << hashed << std::endl;
#endif
                    String sendurl(url);
                    if (!sendurl.after("://").contains("/"))                    {
                        sendurl += "/";
                    }
                    if (sendurl.contains("?"))                    {
                        sendurl = sendurl + "&GSBYPASS=" + hashed + "&N=";
                    }                    else                    {
                        sendurl = sendurl + "?GSBYPASS=" + hashed + "&N=";
                    }
                    sendurl += tempfilename + "&M=" + tempfilemime + "&D=" + tempfiledis;
                    docbody.dm_plugin->sendLink(peerconn, sendurl, url);

                    // can't persist after this - DM plugins don't generally send a Content-Length.
                    //TODO: need to change connection: close if there is plugin involved.
                    persistOutgoing = false;
                }                else                {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -sending body to client" << std::endl;
#endif
                    docbody.out(&peerconn);  // send doc body to client
                }
#ifdef DGDEBUG
                if (pausedtoobig)                {
                    std::cout << dbgPeerPort << " -sent PARTIAL body to client" << std::endl;
                }                else                {
                    std::cout << dbgPeerPort << " -sent body to client" << std::endl;
                }
#endif
                if (pausedtoobig && !docbody.dontsendbody)                {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -about to start tunnel to send the rest" << std::endl;
#endif
                    fdt.reset();
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -1tunnel activated" << std::endl;
#endif
                    fdt.tunnel(proxysock, peerconn, false, docheader.contentLength() - docsize, true);
                    docsize += fdt.throughput;
                    String rtype(header.requestType());
                    if (!logged)                    {
                        doLog(clientuser, clientip, logurl, header.port, exceptionreason,
                              rtype, docsize, &checkme.whatIsNaughtyCategories, false, 0, isexception,
                              docheader.isContentType("text"), &thestart, cachehit, docheader.returnCode(), mimetype,
                              wasinfected, wasscanned, checkme.naughtiness, filtergroup, &header, message_no,
                              contentmodified, urlmodified, headermodified, headeradded);
                    }
                }
            }            else if (!ishead)            {
                // was not supposed to be checked
                fdt.reset();
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -2tunnel activated" << std::endl;
#endif
                fdt.tunnel(proxysock, peerconn, isconnect, docheader.contentLength(), true);
                docsize = fdt.throughput;
                String rtype(header.requestType());
                if (!logged)                {
                    doLog(clientuser, clientip, logurl, header.port, exceptionreason,
                          rtype, docsize, &checkme.whatIsNaughtyCategories, false, 0, isexception,
                          docheader.isContentType("text"), &thestart, cachehit, docheader.returnCode(), mimetype,
                          wasinfected, wasscanned, checkme.naughtiness, filtergroup, &header, message_no,
                          contentmodified, urlmodified, headermodified, headeradded);
                }
            }

            if (!persistProxy)
                proxysock.close();

        } // while persistOutgoing
    }
    catch (postfilter_exception &e)
    {
#ifdef DGDEBUG
        std::cerr << dbgPeerPort << " -connection handler caught a POST filtering exception: " << e.what() << std::endl;
#endif
        syslog(LOG_ERR, "POST filtering exception: %s", e.what());

        // close connection to proxy
        proxysock.close();

        return 0;
    }
    catch (std::exception & e)    {
#ifdef DGDEBUG
        std::cerr << dbgPeerPort << " -connection handler caught an exception: " << e.what() << std::endl;
#endif

        // close connection to proxy
        proxysock.close();

        return 0;
    }

    if (!ismitm) try        {
#ifdef DGDEBUG
            std::cout << dbgPeerPort << " -Attempting graceful connection close" << std::endl;
#endif
            int fd = peerconn.getFD();
            shutdown(fd, SHUT_WR);

            char buff[2];
            peerconn.readFromSocket(buff, 2, 0, 5);

            // close connection to the client
            peerconn.close();
        }
        catch (std::exception & e)        {
#ifdef DGDEBUG
            std::cerr << dbgPeerPort << " -connection handler caught an exception: " << e.what() << std::endl;
#endif
            // close connection to the client
            peerconn.close();
        }

    return 0;
}


// decide whether or not to perform logging, categorise the log entry, and write it.
void ConnectionHandler::doLog(std::string &who, std::string &from, String &where, unsigned int &port,
                              std::string &what, String &how, off_t &size, std::string *cat, bool isnaughty, int naughtytype,
                              bool isexception, bool istext, struct timeval *thestart, bool cachehit,
                              int code, std::string &mimetype, bool wasinfected, bool wasscanned, int naughtiness, int filtergroup,
                              HTTPHeader* reqheader, int message_no, bool contentmodified, bool urlmodified, bool headermodified, bool headeradded)
{

    // don't log if logging disabled entirely, or if it's an ad block and ad logging is disabled,
    // or if it's an exception and exception logging is disabled
    if (
        (o.ll == 0) ||
        ((cat != NULL) && !o.log_ad_blocks && (strstr(cat->c_str(),"ADs") != NULL)) ||
        ((o.log_exception_hits == 0) && isexception))
    {
#ifdef DGDEBUG
        if (o.ll != 0)
        {
            if (isexception)
                std::cout << dbgPeerPort << " -Not logging exceptions" << std::endl;
            else
                std::cout << dbgPeerPort << " -Not logging 'ADs' blocks" << std::endl;
        }
#endif
        return;
    }

    std::string data, cr("\n");

    if ((isexception && (o.log_exception_hits == 2))
            || isnaughty || o.ll == 3 || (o.ll == 2 && istext))
    {
        // put client hostname in log if enabled.
        // for banned & exception IP/hostname matches, we want to output exactly what was matched against,
        // be it hostname or IP - therefore only do lookups here when we don't already have a cached hostname,
        // and we don't have a straight IP match agaisnt the banned or exception IP lists.
        if (o.log_client_hostnames && (clienthost == NULL) && !matchedip && !o.anonymise_logs)        {
#ifdef DGDEBUG
            std::cout<<"logclienthostnames enabled but reverseclientiplookups disabled; lookup forced."<<std::endl;
#endif
            std::deque<String> *names = ipToHostname(from.c_str());
            if (names->size() > 0)
                clienthost = new std::string(names->front().toCharArray());
            delete names;
        }

        // Search 'log-only' domain, url and regexp url lists
        std::string *newcat = NULL;
        if (!cat || cat->length() == 0)        {
#ifdef DGDEBUG
            std::cout << dbgPeerPort << " -Checking for log-only categories" << std::endl;
#endif
            const char* c = o.fg[filtergroup]->inLogSiteList(where);
#ifdef DGDEBUG
            if (c) std::cout << dbgPeerPort << " -Found log-only domain category: " << c << std::endl;
#endif
            if (!c)            {
                c = o.fg[filtergroup]->inLogURLList(where);
#ifdef DGDEBUG
                if (c) std::cout << dbgPeerPort << " -Found log-only URL category: " << c << std::endl;
#endif
            }
            if (!c)            {
                c = o.fg[filtergroup]->inLogRegExpURLList(where);
#ifdef DGDEBUG
                if (c) std::cout << dbgPeerPort << " -Found log-only regexp URL category: " << c << std::endl;
#endif
            }
            if (c)            {
                newcat = new std::string(c);
                cat = newcat;
            }
        }
#ifdef DGDEBUG
        else
            std::cout << dbgPeerPort << " -Not looking for log-only category; current cat string is: " << *cat << " (" << cat->length() << ")" << std::endl;
#endif

        // Build up string describing POST data parts, if any
        std::ostringstream postdata;
        for (std::list<postinfo>::iterator i = postparts.begin(); i != postparts.end(); ++i)
        {
            // Replace characters which would break log format with underscores
            std::string::size_type loc = 0;
            while ((loc = i->filename.find_first_of(",;\t ", loc)) != std::string::npos)
                i->filename[loc] = '_';
            // Build up contents of log column
            postdata << i->mimetype << "," << i->filename << "," << i->size
            << "," << i->blocked << "," << i->storedname << "," << i->bodyoffset << ";";
        }
        postdata << std::flush;

        // Formatting code moved into log_listener in FatController.cpp
        // Original patch by J. Gauthier

        // Item length limit put back to avoid log listener
        // overload with very long urls Philip Pearce Jan 2014
        if ((cat != NULL) && (cat->length() > o.max_logitem_length))
            cat->resize(o.max_logitem_length);
        if (what.length() > o.max_logitem_length)
            what.resize(o.max_logitem_length);
        if (where.length() > o.max_logitem_length)
            where.limitLength(o.max_logitem_length);

#ifdef DGDEBUG
        std::cout << dbgPeerPort << " -Building raw log data string... ";
#endif

        data = String(isexception)+cr;
        data += ( cat ? (*cat) + cr : cr);
        data += String(isnaughty)+cr;
        data += String(naughtytype)+cr;
        data += String(naughtiness)+cr;
        data += where+cr;
        data += what+cr;
        data += how+cr;
        data += who+cr;
        data += from+cr;
        data += String(port)+cr;
        data += String(wasscanned)+cr;
        data += String(wasinfected)+cr;
        data += String(contentmodified)+cr;
        data += String(urlmodified)+cr;
        data += String(headermodified)+cr;
        data += String(size)+cr;
        data += String(filtergroup)+cr;
        data += String(code)+cr;
        data += String(cachehit)+cr;
        data += String(mimetype)+cr;
        data += String((*thestart).tv_sec)+cr;
        data += String((*thestart).tv_usec)+cr;
        data += (clienthost ? (*clienthost) + cr : cr);
        if (o.log_user_agent)
            data += (reqheader ? reqheader->userAgent() + cr : cr);
        else
            data += cr;
        data += urlparams + cr;
        data += postdata.str().c_str() + cr;
        data += String(message_no)+cr;
        data += String(headeradded)+cr;

#ifdef DGDEBUG
        std::cout << dbgPeerPort << " -...built" << std::endl;
#endif

        delete newcat;

        // connect to dedicated logging proc
        UDSocket ipcsock;
        if (ipcsock.getFD() < 0)        {
            if (!is_daemonised)
                std::cout << " -Error creating IPC socket to log" << std::endl;
            syslog(LOG_ERR, "Error creating IPC socket to log");
            return;
        }
        if (ipcsock.connect(o.ipc_filename.c_str()) < 0)        {
            if (!is_daemonised)
                std::cout << " -Error connecting via IPC socket to log: " << strerror(errno) << std::endl;
            syslog(LOG_ERR, "Error connecting via IPC socket to log: %s", strerror(errno));
            ipcsock.close();
            return;
        }

        // send data
        try        {
            ipcsock.setTimeout(10);
            ipcsock.writeString(data.c_str());
            ipcsock.close();
        }        catch (std::exception &e)        {
            syslog(LOG_INFO, "Could not write to logging process: %s", e.what());
#ifdef DGDEBUG
            std::cout << dbgPeerPort << " -Could not write to logging process: " << e.what() << std::endl;
#endif
        }
    }
}

// Request Checks for the eCAP system - can't get several of the params of the original implementation
void ConnectionHandler::requestChecks(HTTPHeader *header, NaughtyFilter *checkme,
        String *urld, String *url, int filtergroup)
{
    std::string empty("");
    bool FALSE = false;

    requestChecks(header, checkme, urld, url, &empty, &empty, filtergroup, FALSE, FALSE, empty);
}

// check the request header is OK (client host/user/IP allowed to browse, site not banned, upload not too big)
void ConnectionHandler::requestChecks(HTTPHeader *header, NaughtyFilter *checkme, String *urld, String *url,
                                      std::string *clientip, std::string *clientuser, int filtergroup,
                                      bool &isbanneduser, bool &isbannedip, std::string &room)
{
    char *i;
    int j;
    String temp;
    temp = (*urld);
    bool is_ssl = header->requestType() == "CONNECT";
    bool is_ip = isIPHostnameStrip(temp);

    // search term blocking - MOVED to after Banned checks

    if ((*o.fg[filtergroup]).enable_regex_grey)    {
        if ((j = (*o.fg[filtergroup]).inBannedRegExpURLList(temp)) >= 0)        {
            (*checkme).isItNaughty = true;
            (*checkme).whatIsNaughtyLog = o.language_list.getTranslation(503);
            (*checkme).message_no = 503;
            // Banned Regular Expression URL
            (*checkme).whatIsNaughtyLog += (*o.fg[filtergroup]).banned_regexpurl_list_source[j].toCharArray();
            (*checkme).whatIsNaughty = o.language_list.getTranslation(504);
            // Banned Regular Expression URL found.
            (*checkme).whatIsNaughtyCategories = (*o.lm.l[(*o.fg[filtergroup]).banned_regexpurl_list_ref[j]]).category.toCharArray();
        }
        else if ((j = o.fg[filtergroup]->inBannedRegExpHeaderList(header->header)) >= 0)        {
            checkme->isItNaughty = true;
            checkme->whatIsNaughtyLog = o.language_list.getTranslation(508);
            (*checkme).message_no = 508;
            checkme->whatIsNaughtyLog += o.fg[filtergroup]->banned_regexpheader_list_source[j].toCharArray();
            checkme->whatIsNaughty = o.language_list.getTranslation(509);
            checkme->whatIsNaughtyCategories = o.lm.l[o.fg[filtergroup]->banned_regexpheader_list_ref[j]]->category.toCharArray();
        }
    }


    if ( checkme->isItNaughty )       // why bother with checking anything else!!!!
    {
#ifdef DGDEBUG
            std::cout << "Returning after first RequestCheck." << std::endl;
#endif
        return;
    }

    if ( !(*checkme).isGrey
            && ( (*o.fg[filtergroup]).inGreySiteList(temp, true, is_ip, is_ssl) || (*o.fg[filtergroup]).inGreyURLList(temp, true, is_ip, is_ssl)))    {
        (*checkme).isGrey = true;
        if (!(*o.fg[filtergroup]).enable_ssl_legacy_logic)
            if (is_ssl) (*checkme).isSSLGrey = true;
    }

    // only apply bans to things not in the grey lists
    if ( !(*checkme).isGrey)    {
        if ((i = (*o.fg[filtergroup]).inBannedSiteList(temp, true, is_ip, is_ssl)) != NULL)        {
            // need to reintroduce ability to produce the blanket block messages
            (*checkme).whatIsNaughty = o.language_list.getTranslation(500);  // banned site
            (*checkme).message_no = 500;
            (*checkme).whatIsNaughty += i;
            (*checkme).whatIsNaughtyLog = (*checkme).whatIsNaughty;
            (*checkme).isItNaughty = true;
            (*checkme).whatIsNaughtyCategories = (*o.lm.l[(*o.fg[filtergroup]).banned_site_list]).lastcategory.toCharArray();
#ifdef DGDEBUG
            std::cout << "Returning, site in banned list" << std::endl;
#endif
            return;
        }
        if ((i = (*o.fg[filtergroup]).inBannedURLList(temp, true, is_ip, is_ssl)) != NULL)        {
            (*checkme).whatIsNaughty = o.language_list.getTranslation(501);
            (*checkme).message_no = 501;
            // Banned URL:
            (*checkme).whatIsNaughty += i;
            (*checkme).whatIsNaughtyLog = (*checkme).whatIsNaughty;
            (*checkme).isItNaughty = true;
            (*checkme).whatIsNaughtyCategories = (*o.lm.l[(*o.fg[filtergroup]).banned_url_list]).lastcategory.toCharArray();
#ifdef DGDEBUG
            std::cout << "Returning, URL in banned list" << std::endl;
#endif
            return;
        }
        // when enable_regex_grey is false no urls will be test against regex
        if (!(*o.fg[filtergroup]).enable_regex_grey)        {
            if ((j = (*o.fg[filtergroup]).inBannedRegExpURLList(temp)) >= 0 )
            {
                (*checkme).isItNaughty = true;
                (*checkme).whatIsNaughtyLog = o.language_list.getTranslation(503);
                (*checkme).message_no = 503;
                // Banned Regular Expression URL:
                (*checkme).whatIsNaughtyLog += (*o.fg[filtergroup]).banned_regexpurl_list_source[j].toCharArray();
                (*checkme).whatIsNaughty = o.language_list.getTranslation(504);
                // Banned Regular Expression URL found.
                (*checkme).whatIsNaughtyCategories = (*o.lm.l[(*o.fg[filtergroup]).banned_regexpurl_list_ref[j]]).category.toCharArray();
#ifdef DGDEBUG
            std::cout << "Returning, URL in banned RegExp URL list" << std::endl;
#endif
                return;
            }
            if ((j = o.fg[filtergroup]->inBannedRegExpHeaderList(header->header)) >= 0)            {
                checkme->isItNaughty = true;
                checkme->whatIsNaughtyLog = o.language_list.getTranslation(508);
                checkme->message_no = 508;
                checkme->whatIsNaughtyLog += o.fg[filtergroup]->banned_regexpheader_list_source[j].toCharArray();
                checkme->whatIsNaughty = o.language_list.getTranslation(509);
                checkme->whatIsNaughtyCategories = o.lm.l[o.fg[filtergroup]->banned_regexpheader_list_ref[j]]->category.toCharArray();
#ifdef DGDEBUG
            std::cout << "Returning, banned RegExp header found" << std::endl;
#endif
                return;
            }
        }
        // look for URLs within URLs - ban, for example, images originating from banned sites during a Google image search.
        if ((*o.fg[filtergroup]).deep_url_analysis)        {
#ifdef DGDEBUG
            std::cout << dbgPeerPort << " -starting deep analysis" << std::endl;
#endif
            String deepurl(temp.after("p://"));
            deepurl = header->decode(deepurl,true);
            while (deepurl.contains(":"))            {
                deepurl = deepurl.after(":");
                while (deepurl.startsWith(":") || deepurl.startsWith("/"))                {
                    deepurl.lop();
                }
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -deep analysing: " << deepurl << std::endl;
#endif
                if ((*o.fg[filtergroup]).enable_local_list)                {
                    if (o.fg[filtergroup]->inLocalExceptionSiteList(deepurl)
                            || o.fg[filtergroup]->inLocalGreySiteList(deepurl)
                            || o.fg[filtergroup]->inLocalExceptionURLList(deepurl)
                            || o.fg[filtergroup]->inLocalGreyURLList(deepurl))
                    {
#ifdef DGDEBUG
                        std::cout << "deep site found in exception/grey list; skipping" << std::endl;
#endif
                        continue;
                    }
                    if ((i = (*o.fg[filtergroup]).inLocalBannedSiteList(deepurl)) != NULL)                    {
                        (*checkme).whatIsNaughty = o.language_list.getTranslation(500); // banned site
                        (*checkme).message_no = 500;
                        (*checkme).whatIsNaughty += i;
                        (*checkme).whatIsNaughtyLog = (*checkme).whatIsNaughty;
                        (*checkme).isItNaughty = true;
                        (*checkme).whatIsNaughtyCategories = (*o.lm.l[(*o.fg[filtergroup]).local_banned_site_list]).lastcategory.toCharArray();
#ifdef DGDEBUG
                        std::cout << "deep site: " << deepurl << std::endl;
#endif
                    }
                    else if ((i = (*o.fg[filtergroup]).inLocalBannedURLList(deepurl)) != NULL)                    {
                        (*checkme).whatIsNaughty = o.language_list.getTranslation(501);
                        (*checkme).message_no = 501;
                        // Banned URL:
                        (*checkme).whatIsNaughty += i;
                        (*checkme).whatIsNaughtyLog = (*checkme).whatIsNaughty;
                        (*checkme).isItNaughty = true;
                        (*checkme).whatIsNaughtyCategories = (*o.lm.l[(*o.fg[filtergroup]).local_banned_url_list]).lastcategory.toCharArray();
#ifdef DGDEBUG
                        std::cout << "deep url: " << deepurl << std::endl;
#endif
                    }
                }
                if ((!(*checkme).isItNaughty) )                {
                    if ( o.fg[filtergroup]->inExceptionSiteList(deepurl) || o.fg[filtergroup]->inGreySiteList(deepurl)
                            || o.fg[filtergroup]->inExceptionURLList(deepurl) || o.fg[filtergroup]->inGreyURLList(deepurl))

                    {
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -deep site found in exception/grey list; skipping" << std::endl;
#endif
                        continue;
                    }
                    else if ((i = (*o.fg[filtergroup]).inBannedSiteList(deepurl)) != NULL)                    {
                        (*checkme).whatIsNaughty = o.language_list.getTranslation(500); // banned site
                        (*checkme).whatIsNaughty += i;
                        (*checkme).whatIsNaughtyLog = (*checkme).whatIsNaughty;
                        (*checkme).message_no = 500;
                        (*checkme).isItNaughty = true;
                        (*checkme).whatIsNaughtyCategories = (*o.lm.l[(*o.fg[filtergroup]).banned_site_list]).lastcategory.toCharArray();
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -deep site: " << deepurl << std::endl;
#endif
                    }
                    else if ((i = (*o.fg[filtergroup]).inBannedURLList(deepurl)) != NULL)                    {
                        (*checkme).whatIsNaughty = o.language_list.getTranslation(501);
                        (*checkme).message_no = 501;
                        // Banned URL:
                        (*checkme).whatIsNaughty += i;
                        (*checkme).whatIsNaughtyLog = (*checkme).whatIsNaughty;
                        (*checkme).isItNaughty = true;
                        (*checkme).whatIsNaughtyCategories = (*o.lm.l[(*o.fg[filtergroup]).banned_url_list]).lastcategory.toCharArray();
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -deep url: " << deepurl << std::endl;
#endif
                    }
                }
            }
#ifdef DGDEBUG
            std::cout << dbgPeerPort << " -done deep analysis" << std::endl;
#endif

            if ( (*checkme).isItNaughty) {
#ifdef DGDEBUG
            std::cout << "Returning, deep analysis discovered banned stuff" << std::endl;
#endif
                return;
            }
        }
    }

    // if we get here it's to be content checked (so far!)
    // So now check for search etc.

    // search term blocking - apply even to things in grey lists, as it's a form of content filtering
    // Note that we must pass in the non-hex-decoded URL in
    // order for regexes to be able to split up parameters reliably
    (*checkme).isSearch = (*header).isSearch(filtergroup);
    if ((*checkme).isSearch)        {
#ifdef DGDEBUG
            std::cout << dbgPeerPort << "Request was search." << std::endl;
#endif

        if ((i = (*o.fg[filtergroup]).inBannedSearchList((*header).searchwords())) != NULL)            {
#ifdef DGDEBUG
            std::cout << dbgPeerPort << "Identified as banned search" << std::endl;
#endif
            (*checkme).whatIsNaughty = o.language_list.getTranslation(521);
            (*checkme).message_no = 521;
            // Banned search term:
            (*checkme).whatIsNaughty += i;
            (*checkme).whatIsNaughtyLog = (*checkme).whatIsNaughty;
            (*checkme).isItNaughty = true;
            (*checkme).whatIsNaughtyCategories = (*o.lm.l[(*o.fg[filtergroup]).banned_search_list]).lastcategory.toCharArray();
#ifdef DGDEBUG
            std::cout << "Returning, this was a banned search" << std::endl;
#endif
            return;
        }
    } else {
        std::cout << "Request was NOT a search" << std::endl;
    }
    if ((*checkme).isSearch)        {
        String terms;
        terms = (*header).searchterms();
        // search terms are URL parameter type "0"
        urlparams.append("0=").append(terms).append(";");
        if (o.fg[filtergroup]->searchterm_limit > 0)            {
#ifdef DGDEBUG
            std::cout << dbgPeerPort << "Exceeded search term limit" << std::endl;
#endif
            // Add spaces at beginning and end of block before filtering, so
            // that the quick & dirty trick of putting spaces around words
            // (Scunthorpe problem) can still be used, bearing in mind the block
            // of text here is usually very small.
            terms.insert(terms.begin(),' ');
            terms.append(" ");
            checkme->checkme(terms.c_str(), terms.length(), NULL, NULL, filtergroup,
                (o.fg[filtergroup]->searchterm_flag ? o.fg[filtergroup]->searchterm_list : o.fg[filtergroup]->banned_phrase_list),
                 o.fg[filtergroup]->searchterm_limit, true);
            if (checkme->isItNaughty)
            {
                checkme->blocktype = 2;
#ifdef DGDEBUG
                std::cout << "Returning, search term limit exceeded" << std::endl;
#endif
                return;
            }
        }
    }
#ifdef DGDEBUG
    std::cout << "Returning, not blocked" << std::endl;
#endif
}

// check the request header is OK (client host/user/IP allowed to browse, site not banned, upload not too big)
void ConnectionHandler::requestLocalChecks(HTTPHeader *header, NaughtyFilter *checkme, String *urld, String *url,
        std::string *clientip, std::string *clientuser, int filtergroup,
        bool &isbanneduser, bool &isbannedip, std::string &room)
{

    if (isbannedip)    {
        (*checkme).isItNaughty = true;
        (*checkme).whatIsNaughtyLog = o.language_list.getTranslation(100);
        (*checkme).message_no = 100;
        // Your IP address is not allowed to web browse:
        (*checkme).whatIsNaughtyLog += clienthost ? *clienthost : *clientip;
        (*checkme).whatIsNaughty = o.language_list.getTranslation(101);
        (*checkme).message_no = 101;
        // Your IP address is not allowed to web browse.
        if (room.empty())
            (*checkme).whatIsNaughtyCategories = "Banned Client IP";
        else        {
            checkme->whatIsNaughtyCategories = "Banned Room";
            checkme->whatIsNaughtyLog.append(" in ");
            checkme->whatIsNaughtyLog.append(room);
        }
        return;
    }
    else if (isbanneduser)    {
        (*checkme).isItNaughty = true;
        (*checkme).whatIsNaughtyLog = o.language_list.getTranslation(102);
        (*checkme).message_no = 102;
        // Your username is not allowed to web browse:
        (*checkme).whatIsNaughtyLog += (*clientuser);
        (*checkme).whatIsNaughty = (*checkme).whatIsNaughtyLog;
        (*checkme).whatIsNaughtyCategories = "Banned User";
        return;
    }

    char *i;
    int j;
    String temp;
    temp = (*urld);
    bool is_ssl = header->requestType() == "CONNECT";
    bool is_ip = isIPHostnameStrip(temp);

    // search term blocking - MOVED to after Banned checks


    if ( !(*checkme).isGrey
            && ( (*o.fg[filtergroup]).inLocalGreySiteList(temp, true, is_ip, is_ssl) || (*o.fg[filtergroup]).inLocalGreyURLList(temp, true, is_ip, is_ssl)))    {
        (*checkme).isGrey = true;
        if (is_ssl) (*checkme).isSSLGrey = true;
    }

    // only apply bans to things not in the grey lists
    if ( !(*checkme).isGrey)    {
        if ((i = (*o.fg[filtergroup]).inLocalBannedSiteList(temp, true, is_ip, is_ssl)) != NULL)        {
            // need to reintroduce ability to produce the blanket block messages
            (*checkme).whatIsNaughty = o.language_list.getTranslation(560);  // banned site
            (*checkme).message_no = 560;
            (*checkme).whatIsNaughty += i;
            (*checkme).whatIsNaughtyLog = (*checkme).whatIsNaughty;
            (*checkme).isItNaughty = true;
            (*checkme).whatIsNaughtyCategories = (*o.lm.l[(*o.fg[filtergroup]).banned_site_list]).lastcategory.toCharArray();
            return;
        }
        if ((i = (*o.fg[filtergroup]).inLocalBannedURLList(temp, true, is_ip, is_ssl)) != NULL)        {
            (*checkme).whatIsNaughty = o.language_list.getTranslation(561);
            (*checkme).message_no = 561;
            // Banned URL:
            (*checkme).whatIsNaughty += i;
            (*checkme).whatIsNaughtyLog = (*checkme).whatIsNaughty;
            (*checkme).isItNaughty = true;
            (*checkme).whatIsNaughtyCategories = (*o.lm.l[(*o.fg[filtergroup]).banned_url_list]).lastcategory.toCharArray();
            return;
        }

        // look for URLs within URLs - ban, for example, images originating from banned sites during a Google image search.
        // done in main requestChecks

    }

    // if we get here it's to be content checked (so far!)
    // So now check for search etc.

    // NOTE dg/protex search term stuff needs combining!!!!


    // search term blocking - apply even to things in grey lists, as it's a form of content filtering
    // don't bother with SSL sites, though.  note that we must pass in the non-hex-decoded URL in
    // order for regexes to be able to split up parameters reliably.
    if (!is_ssl)    {
        (*checkme).isSearch = (*header).isSearch(filtergroup);
        if ((*checkme).isSearch)        {
            if ((i = (*o.fg[filtergroup]).inLocalBannedSearchList((*header).searchwords())) != NULL)            {
                (*checkme).whatIsNaughty = o.language_list.getTranslation(581);
                (*checkme).message_no = 581;
                // Banned search term:
                (*checkme).whatIsNaughty += i;
                (*checkme).whatIsNaughtyLog = (*checkme).whatIsNaughty;
                (*checkme).isItNaughty = true;
                (*checkme).whatIsNaughtyCategories = (*o.lm.l[(*o.fg[filtergroup]).banned_search_list]).lastcategory.toCharArray();
                return;
            }
        }

// dg code
        String terms;
        if ((*checkme).isSearch)        {
            terms = (*header).searchterms();
            // search terms are URL parameter type "0"
            urlparams.append("0=").append(terms).append(";");
            if (o.fg[filtergroup]->searchterm_limit > 0)            {
                // Add spaces at beginning and end of block before filtering, so
                // that the quick & dirty trick of putting spaces around words
                // (Scunthorpe problem) can still be used, bearing in mind the block
                // of text here is usually very small.
                terms.insert(terms.begin(),' ');
                terms.append(" ");
                checkme->checkme(terms.c_str(), terms.length(), NULL, NULL, filtergroup,
                                 (o.fg[filtergroup]->searchterm_flag ? o.fg[filtergroup]->searchterm_list : o.fg[filtergroup]->banned_phrase_list),
                                 o.fg[filtergroup]->searchterm_limit, true);
                if (checkme->isItNaughty)
                {
                    checkme->blocktype = 2;
                    return;
                }
            }
        }
    }
}



// check if embeded url trusted referer
bool ConnectionHandler::embededRefererChecks(HTTPHeader *header, String *urld, String *url,
        int filtergroup)
{

    char *i;
    int j;
    String temp;
    temp = (*urld);
    temp.hexDecode();

    if ( o.fg[filtergroup]->inRefererExceptionLists(header->getReferer()))    {
        return true;
    }
#ifdef DGDEBUG
    std::cout << dbgPeerPort << " -checking for embed url in " << temp << std::endl;
#endif

    if ( o.fg[filtergroup]->inEmbededRefererLists(temp))    {

        // look for referer URLs within URLs
#ifdef DGDEBUG
        std::cout << dbgPeerPort << " -starting embeded referer deep analysis" << std::endl;
#endif
        String deepurl(temp.after("p://"));
        deepurl = header->decode(deepurl,true);
        while (deepurl.contains(":"))        {
            deepurl = deepurl.after(":");
            while (deepurl.startsWith(":") || deepurl.startsWith("/"))            {
                deepurl.lop();
            }

            if (o.fg[filtergroup]->inRefererExceptionLists(deepurl))
            {
#ifdef DGDEBUG
                std::cout << "deep site found in trusted referer list; " << std::endl;
#endif
                return true;
            }
        }
#ifdef DGDEBUG
        std::cout << dbgPeerPort << " -done embdeded referer deep analysis" << std::endl;
#endif
    }
    return false;
}

// based on patch by Aecio F. Neto (afn@harvest.com.br) - Harvest Consultoria (http://www.harvest.com.br)
// show the relevant banned page/image/CGI based on report level setting, request type etc.
bool ConnectionHandler::denyAccess(Socket * peerconn, Socket * proxysock, HTTPHeader * header, HTTPHeader * docheader,
                                   String * url, NaughtyFilter * checkme, std::string * clientuser, std::string * clientip, int filtergroup,
                                   bool ispostblock, int headersent, bool wasinfected, bool scanerror, bool forceshow)
{
    int reporting_level = o.fg[filtergroup]->reporting_level;
#ifdef DGDEBUG

    std::cout << dbgPeerPort << " -reporting level is " << reporting_level << std::endl;

#endif

    try    // writestring throws exception on error/timeout
    {

        // flags to enable filter/infection bypass hash generation
        bool filterhash = false;
        bool virushash = false;
        // flag to enable internal generation of hashes (i.e. obey the "-1" setting; to allow the modes but disable hash generation)
        // (if disabled, just output '1' or '2' to show that the CGI should generate a filter/virus bypass hash;
        // otherwise, real hashes get put into substitution variables/appended to the ban CGI redirect URL)
        bool dohash = false;
        if (reporting_level > 0)        {
            // generate a filter bypass hash
            if (!wasinfected && ((*o.fg[filtergroup]).bypass_mode != 0) && !ispostblock)            {
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -Enabling filter bypass hash generation" << std::endl;
#endif
                filterhash = true;
                if (o.fg[filtergroup]->bypass_mode > 0)
                    dohash = true;
            }
            // generate an infection bypass hash
            else if (wasinfected && (*o.fg[filtergroup]).infection_bypass_mode != 0)            {
                // only generate if scanerror (if option to only bypass scan errors is enabled)
                if ((*o.fg[filtergroup]).infection_bypass_errors_only ? scanerror : true)                {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -Enabling infection bypass hash generation" << std::endl;
#endif
                    virushash = true;
                    if (o.fg[filtergroup]->infection_bypass_mode > 0)
                        dohash = true;
                }
            }
        }

        // the user is using the full whack of custom banned images and/or HTML templates
        if (reporting_level == 3 || (headersent > 0 && reporting_level > 0))        {
            // if reporting_level = 1 or 2 and headersent then we can't
            // send a redirect so we have to display the template instead

            (*proxysock).close();  // finished with proxy
            (*peerconn).readyForOutput(o.proxy_timeout);

            if ((*header).requestType().startsWith("CONNECT"))            {
                // if it's a CONNECT then headersent can't be set
                // so we don't need to worry about it

                // if preemptive banning is not in place then a redirect
                // is not guaranteed to ban the site so we have to write
                // an access denied page.  Unfortunately IE does not
                // work with access denied pages on SSL more than a few
                // hundred bytes so we have to use a crap boring one
                // instead.  Nothing can be done about it - blame
                // mickysoft.
                //
                // FredB 2013
                // Wrong Microsoft is right, no data will be accepted without hand shake
                // This is a Man in the middle problem with Firefox and IE (can't rewrite a ssl page)
                // 307 redirection Fix the problem for Firefox - only ? -
                // TODO: I guess the right thing to do should be a - SSL - DENIED Webpage 307 redirect and direct"

                if (o.fg[filtergroup]->sslaccess_denied_address.length() != 0)                {
                    // grab either the full category list or the thresholded list
                    std::string cats;
                    cats = checkme->usedisplaycats ? checkme->whatIsNaughtyDisplayCategories : checkme->whatIsNaughtyCategories;
                    String hashed;
                    // generate valid hash locally if enabled
                    if (dohash)                    {
                        hashed = hashedURL(url, filtergroup, clientip, virushash);
                    }
                    // otherwise, just generate flags showing what to generate
                    else if (filterhash)                    {
                        hashed = "1";
                    }
                    else if (virushash)                    {
                        hashed = "2";
                    }

                    String writestring("HTTP/1.1 307 Temporary Redirect\n");
                    writestring += "Location: ";
                    writestring +=  o.fg[filtergroup]->sslaccess_denied_address;  // banned site for ssl
                    if (o.fg[filtergroup]->non_standard_delimiter)                    {
                        writestring += "?DENIEDURL==";
                        writestring += miniURLEncode((*url).toCharArray()).c_str();
                        writestring += "::IP==";
                        writestring += (*clientip).c_str();
                        writestring += "::USER==";
                        writestring += (*clientuser).c_str();
                        if (clienthost != NULL)                        {
                            writestring += "::HOST==";
                            writestring += clienthost->c_str();
                        }
                        writestring += "::CATEGORIES==";
                        writestring += miniURLEncode(cats.c_str()).c_str();
                        writestring += "::REASON==";
                    }                    else                    {
                        writestring += "?DENIEDURL=";
                        writestring += miniURLEncode((*url).toCharArray()).c_str();
                        writestring += "&IP=";
                        writestring += (*clientip).c_str();
                        writestring += "&USER=";
                        writestring += (*clientuser).c_str();
                        if (clienthost != NULL)                        {
                            writestring += "&HOST=";
                            writestring += clienthost->c_str();
                        }
                        writestring += "&CATEGORIES=";
                        writestring += miniURLEncode(cats.c_str()).c_str();
                        writestring += "&REASON=";
                    }

                    if (reporting_level == 1)                    {
                        writestring += miniURLEncode((*checkme).whatIsNaughty.c_str()).c_str();
                    }                    else                    {
                        writestring += miniURLEncode((*checkme).whatIsNaughtyLog.c_str()).c_str();
                    }
                    writestring += "\nContent-Length: 0";
                    writestring += "\nCache-control: no-cache";
                    writestring += "\nConnection: close\n";
                    try   // writestring throws exception on error/timeout
                    {
                        (*peerconn).writeString(writestring.toCharArray());
                    }
                    catch (std::exception & e)                    {
                    }
#ifdef DGDEBUG			// debug stuff surprisingly enough
                    std::cout << dbgPeerPort << " -******* redirecting to:" << std::endl;
                    std::cout << dbgPeerPort << writestring << std::endl;
                    std::cout << dbgPeerPort << " -*******" << std::endl;
#endif
                }                else                {
                    // Broken, sadly blank page for user
                    // See comment above HTTPS
                    String writestring("HTTP/1.0 403 ");
                    writestring += o.language_list.getTranslation(500);  // banned site
                    writestring += "\nContent-Type: text/html\n\n<HTML><HEAD><TITLE>e2guardian - ";
                    writestring += o.language_list.getTranslation(500);  // banned site
                    writestring += "</TITLE></HEAD><BODY><H1>e2guardian - ";
                    writestring += o.language_list.getTranslation(500);  // banned site
                    writestring += "</H1>";
                    writestring += (*url);
                    writestring += "</BODY></HTML>\n";
                    try     // writestring throws exception on error/timeout
                    {
                        (*peerconn).writeString(writestring.toCharArray());
                    }
                    catch (std::exception & e)                    {
                    }
                }

            }            else            {
                // we're dealing with a non-SSL'ed request, and have the option of using the custom banned image/page directly
                bool replaceimage = false;
                bool replaceflash = false;
                if (o.use_custom_banned_image)                {

                    // It would be much nicer to do a mime comparison
                    // and see if the type is image/* but the header
                    // never (almost) gets back from squid because
                    // it gets denied before then.
                    // This method is prone to over image replacement
                    // but will work most of the time.

                    String lurl((*url));
                    lurl.toLower();
                    if (lurl.endsWith(".gif") || lurl.endsWith(".jpg") || lurl.endsWith(".jpeg") || lurl.endsWith(".jpe")
                            || lurl.endsWith(".png") || lurl.endsWith(".bmp") || (*docheader).isContentType("image/"))
                    {
                        replaceimage = true;
                    }
                }

                if (o.use_custom_banned_flash)                {
                    String lurl((*url));
                    lurl.toLower();
                    if (lurl.endsWith(".swf") || (*docheader).isContentType("application/x-shockwave-flash"))
                    {
                        replaceflash = true;
                    }
                }

                // if we're denying an image request, show the image; otherwise, show the HTML page.
                // (or advanced ad block page, or HTML page with bypass URLs)
                if (replaceimage)                {
                    if (headersent == 0)                    {
                        (*peerconn).writeString("HTTP/1.0 200 OK\n");
                    }
                    o.banned_image.display(peerconn);
                }
                else if (replaceflash)
                {
                    if (headersent == 0)                    {
                        (*peerconn).writeString("HTTP/1.0 200 OK\n");
                    }
                    o.banned_flash.display(peerconn);
                }                else                {
                    // advanced ad blocking - if category contains ADs, wrap ad up in an "ad blocked" message,
                    // which provides a link to the original URL if you really want it. primarily
                    // for IFRAMEs, which will end up containing this link instead of the ad (standard non-IFRAMEd
                    // ad images still get image-replaced.)
                    if (strstr(checkme->whatIsNaughtyCategories.c_str(), "ADs") != NULL)                    {
                        String writestring("HTTP/1.0 200 ");
                        writestring += o.language_list.getTranslation(1101); // advert blocked
                        writestring += "\nContent-Type: text/html\n\n<HTML><HEAD><TITLE>Guardian - ";
                        writestring += o.language_list.getTranslation(1101); // advert blocked
                        writestring += "</TITLE></HEAD><BODY><CENTER><FONT SIZE=\"-1\"><A HREF=\"";
                        writestring += (*url);
                        writestring += "\" TARGET=\"_BLANK\">";
                        writestring += o.language_list.getTranslation(1101); // advert blocked
                        writestring += "</A></FONT></CENTER></BODY></HTML>\n";
                        try   // writestring throws exception on error/timeout
                        {
                            (*peerconn).writeString(writestring.toCharArray());
                        }                        catch (std::exception& e) {}
                    }

                    // Mod by Ernest W Lessenger Mon 2nd February 2004
                    // Other bypass code mostly written by Ernest also
                    // create temporary bypass URL to show on denied page
                    else                    {
                        String hashed;
                        // generate valid hash locally if enabled
                        if (dohash)                        {
                            hashed = hashedURL(url, filtergroup, clientip, virushash);
                        }
                        // otherwise, just generate flags showing what to generate
                        else if (filterhash)                        {
                            hashed = "HASH=1";
                        }
                        else if (virushash)                        {
                            hashed = "HASH=2";
                        }

                        if (headersent == 0)                        {
                            (*peerconn).writeString("HTTP/1.0 200 OK\n");
                        }
                        if (headersent < 2)                        {
                            (*peerconn).writeString("Content-type: text/html\n\n");
                        }
                        // if the header has been sent then likely displaying the
                        // template will break the download, however as this is
                        // only going to be happening if the unsafe trickle
                        // buffer method is used and we want the download to be
                        // broken we don't mind too much
                        String fullurl = header->getLogUrl(true);
                        o.fg[filtergroup]->getHTMLTemplate()->display(peerconn,
                                &fullurl, (*checkme).whatIsNaughty, (*checkme).whatIsNaughtyLog,
                                // grab either the full category list or the thresholded list
                                (checkme->usedisplaycats ? checkme->whatIsNaughtyDisplayCategories : checkme->whatIsNaughtyCategories),
                                clientuser, clientip, clienthost, filtergroup, hashed);
                    }
                }
            }
        }

        // the user is using the CGI rather than the HTML template - so issue a redirect with parameters filled in on GET string
        else if (reporting_level > 0)        {
            // grab either the full category list or the thresholded list
            std::string cats;
            cats = checkme->usedisplaycats ? checkme->whatIsNaughtyDisplayCategories : checkme->whatIsNaughtyCategories;

            String hashed;
            // generate valid hash locally if enabled
            if (dohash)            {
                hashed = hashedURL(url, filtergroup, clientip, virushash);
            }
            // otherwise, just generate flags showing what to generate
            else if (filterhash)            {
                hashed = "1";
            }
            else if (virushash)            {
                hashed = "2";
            }

            (*proxysock).close();  // finshed with proxy
            (*peerconn).readyForOutput(o.proxy_timeout);
            if ((*checkme).whatIsNaughty.length() > 2048)            {
                (*checkme).whatIsNaughty = String((*checkme).whatIsNaughty.c_str()).subString(0, 2048).toCharArray();
            }
            if ((*checkme).whatIsNaughtyLog.length() > 2048)            {
                (*checkme).whatIsNaughtyLog = String((*checkme).whatIsNaughtyLog.c_str()).subString(0, 2048).toCharArray();
            }
            String writestring("HTTP/1.0 302 Redirect\n");
            writestring += "Location: ";
            writestring += o.fg[filtergroup]->access_denied_address;

            if (o.fg[filtergroup]->non_standard_delimiter)            {
                writestring += "?DENIEDURL==";
                writestring += miniURLEncode((*url).toCharArray()).c_str();
                writestring += "::IP==";
                writestring += (*clientip).c_str();
                writestring += "::USER==";
                writestring += (*clientuser).c_str();
                if (clienthost != NULL)                {
                    writestring += "::HOST==";
                    writestring += clienthost->c_str();
                }
                writestring += "::CATEGORIES==";
                writestring += miniURLEncode(cats.c_str()).c_str();
                if (virushash || filterhash)                {
                    // output either a genuine hash, or just flags
                    if (dohash)                    {
                        writestring += "::";
                        writestring += hashed.before("=").toCharArray();
                        writestring += "==";
                        writestring += hashed.after("=").toCharArray();
                    }                    else                    {
                        writestring += "::HASH==";
                        writestring += hashed.toCharArray();
                    }
                }
                writestring += "::REASON==";
            }            else            {
                writestring += "?DENIEDURL=";
                writestring += miniURLEncode((*url).toCharArray()).c_str();
                writestring += "&IP=";
                writestring += (*clientip).c_str();
                writestring += "&USER=";
                writestring += (*clientuser).c_str();
                if (clienthost != NULL)                {
                    writestring += "&HOST=";
                    writestring += clienthost->c_str();
                }
                writestring += "&CATEGORIES=";
                writestring += miniURLEncode(cats.c_str()).c_str();
                if (virushash || filterhash)                {
                    // output either a genuine hash, or just flags
                    if (dohash)                    {
                        writestring += "&";
                        writestring += hashed.toCharArray();
                    }                    else                    {
                        writestring += "&HASH=";
                        writestring += hashed.toCharArray();
                    }
                }
                writestring += "&REASON=";
            }
            if (reporting_level == 1)            {
                writestring += miniURLEncode((*checkme).whatIsNaughty.c_str()).c_str();
            }            else            {
                writestring += miniURLEncode((*checkme).whatIsNaughtyLog.c_str()).c_str();
            }
            writestring += "\n\n";
            (*peerconn).writeString(writestring.toCharArray());
#ifdef DGDEBUG			// debug stuff surprisingly enough
            std::cout << dbgPeerPort << " -******* redirecting to:" << std::endl;
            std::cout << dbgPeerPort << writestring << std::endl;
            std::cout << dbgPeerPort << " -*******" << std::endl;
#endif
        }

        // the user is using the barebones banned page
        else if (reporting_level == 0)        {
            (*proxysock).close();  // finshed with proxy
            String writestring("HTTP/1.0 200 OK\n");
            writestring += "Content-type: text/html\n\n";
            writestring += "<HTML><HEAD><TITLE>e2guardian - ";
            writestring += o.language_list.getTranslation(1);  // access denied
            writestring += "</TITLE></HEAD><BODY><CENTER><H1>e2guardian - ";
            writestring += o.language_list.getTranslation(1);  // access denied
            writestring += "</H1></CENTER></BODY></HTML>";
            (*peerconn).readyForOutput(o.proxy_timeout);
            (*peerconn).writeString(writestring.toCharArray());
#ifdef DGDEBUG			// debug stuff surprisingly enough
            std::cout << dbgPeerPort << " -******* displaying:" << std::endl;
            std::cout << dbgPeerPort << writestring << std::endl;
            std::cout << dbgPeerPort << " -*******" << std::endl;
#endif
        }

        // stealth mode
        else if (reporting_level == -1)        {
            (*checkme).isItNaughty = false;  // dont block
        }
    }
    catch (std::exception & e)    {
    }

    // we blocked the request, so flush the client connection & close the proxy connection.
    if ((*checkme).isItNaughty)    {
        try        {
            (*peerconn).readyForOutput(o.proxy_timeout);  //as best a flush as I can
        }
        catch (std::exception & e)        {
        }
        (*proxysock).close();  // close connection to proxy
        // we said no to the request, so return true, indicating exit the connhandler
        return true;
    }
    return false;
}

// do content scanning (AV filtering) and naughty filtering
void ConnectionHandler::contentFilter(HTTPHeader *docheader, HTTPHeader *header, DataBuffer *docbody,
                                      BaseSocket *proxysock, BaseSocket *peerconn, int *headersent, bool *pausedtoobig, off_t *docsize, NaughtyFilter *checkme,
                                      bool wasclean, int filtergroup, std::deque<CSPlugin *> &responsescanners,
                                      std::string *clientuser, std::string *clientip, bool *wasinfected, bool *wasscanned, bool isbypass,
                                      String &url, String &domain, bool *scanerror, bool &contentmodified, String *csmessage)
{
    int rc = 0;

    proxysock->checkForInput(3);
    bool compressed = docheader->isCompressed();
    if (compressed)    {
#ifdef DGDEBUG
        std::cout << dbgPeerPort << " -Decompressing as we go....." << std::endl;
#endif
        docbody->setDecompress(docheader->contentEncoding());
    }
#ifdef DGDEBUG
    std::cout << dbgPeerPort << docheader->contentEncoding() << std::endl;
    std::cout << dbgPeerPort << " -about to get body from proxy" << std::endl;
#endif
    (*pausedtoobig) = docbody->in(proxysock, peerconn, header, docheader, !responsescanners.empty(), headersent);  // get body from proxy
    // checkme: surely if pausedtoobig is true, we just want to break here?
    // the content is larger than max_content_filecache_scan_size if it was downloaded for scanning,
    // and larger than max_content_filter_size if not.
    // in fact, why don't we check the content length (when it's not -1) before even triggering the download managers?
#ifdef DGDEBUG
    if ((*pausedtoobig))    {
        std::cout << dbgPeerPort << " -got PARTIAL body from proxy" << std::endl;
    }    else    {
        std::cout << dbgPeerPort << " -got body from proxy" << std::endl;
    }
#endif
    off_t dblen;
    bool isfile = false;
    if (docbody->tempfilesize > 0)    {
        dblen = docbody->tempfilesize;
        isfile = true;
    }    else    {
        dblen = docbody->buffer_length;
    }
    // don't scan zero-length buffers (waste of AV resources, especially with external scanners (ICAP)).
    // these were encountered browsing opengroup.org, caused by a stats script. (PRA 21/09/2005)
    // if we wanted to honour a hypothetical min_content_scan_size, we'd do it here.
    if (((*docsize) = dblen) == 0)    {
#ifdef DGDEBUG
        std::cout << dbgPeerPort << " -Not scanning zero-length body" << std::endl;
#endif
        // it's not inconceivable that we received zlib or gzip encoded content
        // that is, after decompression, zero length. we need to cater for this.
        // seen on SW's internal MediaWiki.
        docbody->swapbacktocompressed();
        return;
    }

    if (!wasclean)  	// was not clean or no urlcache
    {

        // fixed to obey maxcontentramcachescansize
        if (!responsescanners.empty() && (isfile ? dblen <= o.max_content_filecache_scan_size : dblen <= o.max_content_ramcache_scan_size))
        {
            int csrc = 0;
#ifdef DGDEBUG
            int k = 0;
#endif
            for (std::deque<CSPlugin *>::iterator i = responsescanners.begin(); i != responsescanners.end(); i++)            {
                (*wasscanned) = true;
                if (isfile)                {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -Running scanFile" << std::endl;
#endif
                    csrc = (*i)->scanFile(header, docheader, clientuser->c_str(), filtergroup, clientip->c_str(), docbody->tempfilepath.toCharArray(), checkme);
                    if ((csrc != DGCS_CLEAN) && (csrc != DGCS_WARNING))                    {
                        unlink(docbody->tempfilepath.toCharArray());
                        // delete infected (or unscanned due to error) file straight away
                    }
                }                else                {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -Running scanMemory" << std::endl;
#endif
                    csrc = (*i)->scanMemory(header, docheader, clientuser->c_str(), filtergroup, clientip->c_str(), docbody->data, docbody->buffer_length, checkme);
                }
#ifdef DGDEBUG
                std::cerr << dbgPeerPort << " -AV scan " << k << " returned: " << csrc << std::endl;
#endif
                if (csrc == DGCS_WARNING)                {
                    // Scanner returned a warning. File wasn't infected, but wasn't scanned properly, either.
                    (*wasscanned) = false;
                    (*scanerror) = false;
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << (*i)->getLastMessage() << std::endl;
#endif
                    (*csmessage) = (*i)->getLastMessage();
                }
                else if (csrc == DGCS_BLOCKED)                {
                    (*wasscanned) = true;
                    (*scanerror) = false;
                    break;
                }
                else if (csrc == DGCS_INFECTED)                {
                    (*wasinfected) = true;
                    (*scanerror) = false;
                    break;
                }
                //if its not clean / we errored then treat it as infected
                else if (csrc != DGCS_CLEAN)                {
                    if (csrc < 0)                    {
                        syslog(LOG_ERR, "Unknown return code from content scanner: %d", csrc);
                    }
                    else                    {
                        syslog(LOG_ERR, "scanFile/Memory returned error: %d", csrc);
                    }
                    //TODO: have proper error checking/reporting here?
                    //at the very least, integrate with the translation system.
                    //checkme->whatIsNaughty = "WARNING: Could not perform content scan!";
                    checkme->message_no = 1203;
                    checkme->whatIsNaughty = o.language_list.getTranslation(1203);
                    checkme->whatIsNaughtyLog = (*i)->getLastMessage().toCharArray();
                    //checkme->whatIsNaughtyCategories = "Content scanning";
                    checkme->whatIsNaughtyCategories = o.language_list.getTranslation(72);
                    checkme->isItNaughty = true;
                    checkme->isException = false;
                    (*scanerror) = true;
                    break;
                }
#ifdef DGDEBUG
                k++;
#endif
            }

#ifdef DGDEBUG
            std::cout << dbgPeerPort << " -finished running AV" << std::endl;
            rc = system("date");
#endif
        }
#ifdef DGDEBUG
        else if (!responsescanners.empty())        {
            std::cout << dbgPeerPort << " -content length large so skipping content scanning (virus) filtering" << std::endl;
        }
        rc = system("date");
#endif
        if (!checkme->isItNaughty && !checkme->isException && !isbypass && (dblen <= o.max_content_filter_size)
                && !docheader->authRequired() && (docheader->isContentType("text") || docheader->isContentType("-")))
        {
            checkme->checkme(docbody->data, docbody->buffer_length, &url, &domain,
                             filtergroup, o.fg[filtergroup]->banned_phrase_list, o.fg[filtergroup]->naughtyness_limit);
        }
#ifdef DGDEBUG
        else        {
            std::cout << dbgPeerPort << " -Skipping content filtering: ";
            if (dblen > o.max_content_filter_size)
                std::cout << dbgPeerPort << " -Content too large";
            else if (checkme->isException)
                std::cout << dbgPeerPort << " -Is flagged as an exception";
            else if (checkme->isItNaughty)
                std::cout << dbgPeerPort << " -Is already flagged as naughty (content scanning)";
            else if (isbypass)
                std::cout << dbgPeerPort << " -Is flagged as a bypass";
            else if (docheader->authRequired())
                std::cout << dbgPeerPort << " -Is a set of auth required headers";
            else if (!docheader->isContentType("text"))
                std::cout << dbgPeerPort << " -Not text";
            std::cout << dbgPeerPort << std::endl;
        }
#endif
    }

    // don't do phrase filtering or content replacement on exception/bypass accesses
    if (checkme->isException || isbypass)    {
        // don't forget to swap back to compressed!
        docbody->swapbacktocompressed();
        return;
    }

    if ((dblen <= o.max_content_filter_size) && !checkme->isItNaughty && docheader->isContentType("text"))    {
        contentmodified = docbody->contentRegExp(filtergroup);
        // content modifying uses global variable
    }
#ifdef DGDEBUG
    else    {
        std::cout << dbgPeerPort << " -Skipping content modification: ";
        if (dblen > o.max_content_filter_size)
            std::cout << dbgPeerPort << " -Content too large";
        else if (!docheader->isContentType("text"))
            std::cout << dbgPeerPort << " -Not text";
        else if (checkme->isItNaughty)
            std::cout << dbgPeerPort << " -Already flagged as naughty";
        std::cout << dbgPeerPort << std::endl;
    }
    rc = system("date");
#endif

    if (contentmodified)  	// this would not include infected/cured files
    {
        // if the content was modified then it must have fit in ram so no
        // need to worry about swapped to disk stuff
#ifdef DGDEBUG
        std::cout << dbgPeerPort << " -content modification made" << std::endl;
#endif
        if (compressed)        {
            docheader->removeEncoding(docbody->buffer_length);
            // need to modify header to mark as not compressed
            // it also modifies Content-Length as well
        }        else        {
            docheader->setContentLength(docbody->buffer_length);
        }
    }    else    {
        docbody->swapbacktocompressed();
        // if we've not modified it might as well go back to
        // the original compressed version (if there) and send
        // that to the browser
    }
}


