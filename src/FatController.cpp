// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.


// INCLUDES

#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif

#include <sstream>
#include <cstdlib>
#include <syslog.h>
#include <csignal>
#include <ctime>
#include <sys/stat.h>
#include <pwd.h>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include <sys/time.h>
#include <sys/poll.h>

#include <istream>
#include <map>
#include <memory>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>

#ifdef ENABLE_SEGV_BACKTRACE
#include <execinfo.h>
#include <ucontext.h>
#endif

#include "FatController.hpp"
#include "ConnectionHandler.hpp"
#include "DynamicURLList.hpp"
#include "DynamicIPList.hpp"
#include "String.hpp"
#include "SocketArray.hpp"
#include "UDSocket.hpp"
#include "SysV.hpp"

// GLOBALS

// these are used in signal handlers - "volatile" indicates they can change at
// any time, and therefore value reading on them does not get optimised. since
// the values can get altered by outside influences, this is useful.
static volatile bool ttg = false;
static volatile bool gentlereload = false;
static volatile bool sig_term_killall = false;
volatile bool reloadconfig = false;

extern OptionContainer o;
extern bool is_daemonised;

int numsubprocs;  // to keep count of our subprocs
int busysubprocs;  // to keep count of our busy subprocs
int freesubprocs;  // to keep count of our free subprocs
int waitingfor;  // num procs waiting for to be preforked
int cache_erroring;  // num cache errors reported by subprocs
int *subprocspids;  // so when one exits we know who
int *subprocsstates;  // so we know what they're up to
int *subprocsrestart_cnt;  // so we know which restart_cnt subproc was started with
struct pollfd *pids;
int restart_cnt = 0;
int restart_numsubprocs;  // numsubprocs at time of gentle restart
int hup_index;
int gentle_to_hup = 0;
bool gentle_in_progress = false;
time_t next_gentle_check;
int top_subproc_fds; // cross platform maxsubprocs position in subprocs array
UDSocket **subprocsockets;
int failurecount;
UDSocket loggersock;  // the unix domain socket to be used for ipc with the forked subprocs
UDSocket urllistsock;
UDSocket iplistsock;
Socket *peersock(NULL);  // the socket which will contain the connection
String peersockip;  // which will contain the connection ip

//equal to o.max_subprocs because array indices...
//remember, 50 max subprocs means there are 0-49 pids. REQMOD becomes 50 and RESPMOD is 51
int MAX_LISTEN = 384;
UDSocket ecapreqlistener;	// listens on the configured ecap_req_address for REQMOD requests
UDSocket ecapresplistener;	// listens on the configured ecap_resp_address for RESPMOD requests
UDSocket* ecappeer(NULL);	// subproc process use only.  The eCAP peer connection.
ConnectionType connectiontype;	// enum of possible connection types


struct stat_rec
{
    long births;  	// num of subproc forks in stat interval
    long deaths;  	// num of subproc deaths in stat interval
    long conx;  		// num of client connections in stat interval
    time_t start_int;	// time of start of this stat interval
    time_t end_int;		// target end time of stat interval
    FILE *fs;	// file stream
    void reset();
    void start();
    void clear();
    void close();
};

void stat_rec::clear()
{
    births = 0;
    deaths = 0;
    conx = 0;
};

void stat_rec::start()
{
    clear();
    start_int = time(NULL);
    end_int = start_int + o.dstat_interval;
    if ( o.dstat_log_flag )
    {
        mode_t old_umask;
        old_umask = umask(S_IWGRP | S_IWOTH);
        fs = fopen(o.dstat_location.c_str(), "a");
        if (fs)
        {
            fprintf(fs, "time		subprocs 	busy	free	wait	births	deaths	conx	conx/s\n");
        }
        else
        {
            syslog(LOG_ERR, "Unable to open dstats_log %s for writing\nContinuing with logging\n",
                   o.dstat_location.c_str());
            o.dstat_log_flag = false;
        };
        umask(old_umask);
    };

};

void stat_rec::reset()
{
    time_t now = time(NULL);
    long cps = conx / ( now - start_int );
    fprintf(fs,"%ld	%d	%d	%d	%d	%ld	%ld	%ld	%ld\n", now, numsubprocs,
            (busysubprocs - waitingfor),
            freesubprocs,
            waitingfor,
            births,
            deaths,
            conx,
            cps);
    clear();
    if ((end_int + o.dstat_interval) > now)
        start_int = end_int;
    else
        start_int = now;
    end_int = start_int + o.dstat_interval;
};

void stat_rec::close()
{
    fclose(fs);
};

stat_rec dstat;
stat_rec *dystat = &dstat;

// DECLARATIONS

// Signal handlers
extern "C"
{
    void sig_chld(int signo);
    void sig_term(int signo);  // This is so we can kill our subprocs
    void sig_termsafe(int signo);  // This is so we can kill our subprocs safer
    void sig_hup(int signo);  // This is so we know if we should re-read our config.
    void sig_usr1(int signo);  // This is so we know if we should re-read our config but not kill current connections
    void sig_subprocterm(int signo);
#ifdef ENABLE_SEGV_BACKTRACE
    void sig_segv(int signo, siginfo_t *info, void *secret); // Generate a backtrace on segfault
#endif
}

// logging & URL cache processes
int log_listener(std::string log_location, bool logconerror, bool logsyslog);
int url_list_listener(bool logconerror);
// send flush message over URL cache IPC socket
void flush_urlcache();

// fork off into background
bool daemonise();
// create specified amount of subproc processes
int prefork(int num);

// check subproc process is ready to start work
bool check_subproc_readystatus(int tofind);
// subproc process informs parent process that it is ready
int send_readystatus(UDSocket &pipe);

// subproc process main loop - sits waiting for incoming connections & processes them
int handle_connections(UDSocket &pipe);
// tell a non-busy subproc process to accept the incoming connection
void tellsubproc_accept(int num, int whichsock);
// subproc process accept()s connection from server socket
bool getsock_fromparent(UDSocket &fd);

// add known info about a subproc to our info lists
void addsubproc(int pos, int fd, pid_t subproc_pid);
// find ID of first non-busy subproc
int getfreesubproc();
// find an empty slot in our subproc info lists
int getsubprocslot();
// cull up to this number of non-busy subprocs
void cullsubprocs(int num);
// delete this subproc from our info lists
void deletesubproc(int subproc_pid);
void deletesubproc_by_fd(int i);  // i = fd/pos
// clean up any dead subproc processes (calls deletesubproc with exit values)
void mopup_aftersubprocs();

// tidy up resources for a brand new subproc process (uninstall signal handlers, delete copies of unnecessary data, etc.)
void tidyup_forsubproc();

// send SIGTERM or SIGHUP to call subprocs
void kill_allsubprocs();
void hup_allsubprocs();

// setuid() to proxy user (not just seteuid()) - used by subproc processes & logger/URL cache for security & resource usage reasons
bool drop_priv_completely();



// IMPLEMENTATION

// signal handlers
extern "C"  	// The kernel knows nothing of objects so
{
    // we have to have a lump of c
    void sig_term(int signo)
    {
        sig_term_killall = true;
        ttg = true;  // its time to go
    }
    void sig_termsafe(int signo)
    {
        ttg = true;  // its time to go
    }
    void sig_hup(int signo)
    {
        reloadconfig = true;
#ifdef DGDEBUG
        std::cout << "HUP received." << std::endl;
#endif
    }
    void sig_usr1(int signo)
    {
        gentlereload = true;
#ifdef DGDEBUG
        std::cout << "USR1 received." << std::endl;
#endif
    }
    void sig_subprocterm(int signo)
    {
#ifdef DGDEBUG
        std::cout << "TERM received." << std::endl;
#endif
        _exit(0);
    }
#ifdef ENABLE_SEGV_BACKTRACE
    void sig_segv(int signo, siginfo_t *info, void *secret)
    {
#ifdef DGDEBUG
        std::cout << "SEGV received." << std::endl;
#endif
        // Extract "real" info about first stack frame
        ucontext_t *uc = (ucontext_t *) secret;
#ifdef REG_EIP
        syslog(LOG_ERR, "SEGV received: memory address %p, EIP %p", info->si_addr, (void *)(uc->uc_mcontext.gregs[REG_EIP]));
#else
        syslog(LOG_ERR, "SEGV received: memory address %p, RIP %p", info->si_addr, (void *)(uc->uc_mcontext.gregs[REG_RIP]));
#endif
        // Generate backtrace
        void *addresses[10];
        char **strings;
        int c = backtrace(addresses, 10);
        // Overwrite call to sigaction with caller's address
        // to give a more useful backtrace
#ifdef REG_EIP
        addresses[1] = (void *)(uc->uc_mcontext.gregs[REG_EIP]);
#else
        addresses[1] = (void *)(uc->uc_mcontext.gregs[REG_RIP]);
#endif
        strings = backtrace_symbols(addresses,c);
        printf("backtrace returned: %d\n", c);
        // Skip first stack frame - it points to this signal handler
        for (int i = 1; i < c; i++)
        {
            syslog(LOG_ERR, "%d: %zX ", i, (size_t)addresses[i]);
            syslog(LOG_ERR, "%s", strings[i]);
        }
        // Kill off the current process
        raise(SIGTERM);
    }
#endif
}

// completely drop our privs - i.e. setuid, not just seteuid
bool drop_priv_completely()
{
    // This is done to solve the problem where the total processes for the
    // uid rather than euid is taken for RLIMIT_NPROC and so can't fork()
    // as many as expected.
    // It is also more secure.
    //
    // Suggested fix by Lawrence Manning Tue 25th February 2003
    //

    int rc = seteuid(o.root_user);  // need to be root again to drop properly
    if (rc == -1)
    {
        syslog(LOG_ERR, "%s", "Unable to seteuid(suid)");
#ifdef DGDEBUG
        std::cout << strerror(errno) << std::endl;
#endif
        return false;  // setuid failed for some reason so exit with error
    }
    rc = setuid(o.proxy_user);
    if (rc == -1)
    {
        syslog(LOG_ERR, "%s", "Unable to setuid()");
        return false;  // setuid failed for some reason so exit with error
    }
    return true;
}

// signal the URL cache to flush via IPC
void flush_urlcache()
{
    if (o.url_cache_number < 1)
    {
        return;  // no cache running to flush
    }
    UDSocket fipcsock;
    if (fipcsock.getFD() < 0)
    {
        syslog(LOG_ERR, "%s", "Error creating ipc socket to url cache for flush");
        return;
    }
    if (fipcsock.connect(o.urlipc_filename.c_str()) < 0)  	// conn to dedicated url cach proc
    {
        syslog(LOG_ERR, "%s", "Error connecting via ipc to url cache for flush");
#ifdef DGDEBUG
        std::cout << "Error connecting via ipc to url cache for flush" << std::endl;
#endif
        return;
    }
    String request("f\n");
    try
    {
        fipcsock.writeString(request.toCharArray());  // throws on err
    }
    catch (std::exception & e)
    {
#ifdef DGDEBUG
        std::cerr << "Exception flushing url cache" << std::endl;
        std::cerr << e.what() << std::endl;
#endif
        syslog(LOG_ERR, "%s", "Exception flushing url cache");
        syslog(LOG_ERR, "%s", e.what());
    }
}

// Fork ourselves off into the background
bool daemonise()
{

    if (o.no_daemon)
    {
        return true;
    }
#ifdef DGDEBUG
    return true;  // if debug mode is enabled we don't want to detach
#endif

    if (is_daemonised)
    {
        return true;  // we are already daemonised so this must be a
        // reload caused by a HUP
    }

    int nullfd = -1;
    if ((nullfd = open("/dev/null", O_WRONLY, 0)) == -1)
    {
        syslog(LOG_ERR, "%s", "Couldn't open /dev/null");
        return false;
    }

    pid_t pid;
    if ((pid = fork()) < 0)
    {
        // Error!!
        close(nullfd);
        return false;
    }
    else if (pid != 0)
    {
        // parent goes...
        if (nullfd != -1)
        {
            close(nullfd);
        }

        // bye-bye
        exit(0);
    }

    // subproc continues
    dup2(nullfd, 0);  // stdin
    dup2(nullfd, 1);  // stdout
    dup2(nullfd, 2);  // stderr
    close(nullfd);

    setsid();  // become session leader
    int dummy = chdir("/");  // change working directory
    umask(0);  // clear our file mode creation mask
    umask(S_IWGRP | S_IWOTH);  // set to mor sensible setting??

    is_daemonised = true;

    return true;
}


// *
// *
// *  subproc process code
// *
// *

// prefork specified num of subprocs and set them handling connections
int prefork(int num)
{
    if (num < waitingfor)
    {
        return 3;  // waiting for forks already
    }
#ifdef DGDEBUG
    std::cout << "attempting to prefork:" << num << std::endl;
#endif
    int sv[2];
    pid_t subproc_pid;
    while (num--)
    {

        // e2 can't creates a number of process equal to maxsubprocs, -1 is needed for seeing saturation
        if (!(numsubprocs < (o.max_subprocs -1)))
        {
            syslog(LOG_ERR, "E2guardian is running out of Maxsubprocs process: %d maxsubprocs: %d\n", numsubprocs, o.max_subprocs);
            return 2;  // too many - geddit?
        }

        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
        {
            syslog(LOG_ERR, "Error %d from socketpair: %s", errno, strerror(errno));
            return -1;  // error
        }
        subproc_pid = fork();

        if (subproc_pid == -1)  	// fork failed, for example, if the
        {
            // process is not allowed to create
            // any more
            syslog(LOG_ERR, "%s", "Unable to fork() any more.");
#ifdef DGDEBUG
            std::cout << "Unable to fork() any more." << std::endl;
            std::cout << strerror(errno) << std::endl;
            std::cout << "numsubprocs:" << numsubprocs << std::endl;
#endif
            failurecount++;  // log the error/failure
            // A DoS attack on a server allocated
            // too many subprocs in the conf will
            // kill the server.  But this is user
            // error.
            sleep(1);  // need to wait until we have a spare slot
            num--;
            continue;  // Nothing doing, go back to listening
        }
        else if (subproc_pid == 0)
        {
            // I am the subproc - I am alive!
            close(sv[0]);  // we only need our copy of this
            tidyup_forsubproc();
            if (!drop_priv_completely())
            {
                return -1;  //error
            }
            // no need to deallocate memory etc as already done when fork()ed
            // right - let's do our job!

            //  code to make fd low number
            int low_fd = dup(sv[1]);
            if (low_fd < 0)
            {
                return -1;  //error
            }
            //close(sv[1]);
            //sv[1] = low_fd;
            UDSocket sock(low_fd);
            //UDSocket sock(sv[1]);
            int rc = handle_connections(sock);

            // ok - job done, time to tidy up.
            _exit(rc);  // baby go bye bye
        }
        else
        {
            // I am the parent
            // close the end of the socketpair we don't need
            close(sv[1]);

            int subproc_slot;
#ifdef DGDEBUG
            std::cout << "subproc_slot" << subproc_slot << std::endl;
#endif

            // add the subproc and its FD/PID to an empty subproc slot
            /* Fix BSD Crash */
            if ((subproc_slot = getsubprocslot()) >= 0)
            {
                if (o.logsubprocs)
                {
                    syslog(LOG_ERR, "Adding subproc to slot %d (pid %d)", subproc_slot, subproc_pid);
                }
                addsubproc(subproc_slot, sv[0], subproc_pid);
            }
            else
            {
                if (o.logsubprocs)
                {
                    syslog(LOG_ERR, "Prefork - subproc fd (%d) out of range (max %d)", sv[0], o.max_subprocs);
                }
                close(sv[0]);
                kill(subproc_pid,SIGTERM);
                return(1);
            }

#ifdef DGDEBUG
            std::cout << "Preforked parent added subproc to list" << std::endl;
#endif
            dystat->births++;
        }
    }
    return 1;  // parent returning
}

// cleaning up for brand new subproc processes - only the parent needs the signal handlers installed, and so forth
void tidyup_forsubproc()
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = &sig_subprocterm;
    if (sigaction(SIGTERM, &sa, NULL))  	// restore sig handler
    {
        // in subproc process
#ifdef DGDEBUG
        std::cerr << "Error resetting signal for SIGTERM" << std::endl;
#endif
        syslog(LOG_ERR, "%s", "Error resetting signal for SIGTERM");
    }
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGUSR1, &sa, NULL))  	// restore sig handler
    {
        // in subproc process
#ifdef DGDEBUG
        std::cerr << "Error resetting signal for SIGUSR1" << std::endl;
#endif
        syslog(LOG_ERR, "%s", "Error resetting signal for SIGUSR1");
    }
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = &sig_hup;
    if (sigaction(SIGHUP, &sa, NULL))  	// restore sig handler
    {
        // in subproc process
#ifdef DGDEBUG
        std::cerr << "Error resetting signal for SIGHUP" << std::endl;
#endif
        syslog(LOG_ERR, "%s", "Error resetting signal for SIGHUP");
    }
    // now close open socket pairs don't need
    for (int i = 0; i < o.max_subprocs; i++)
    {
        if (pids[i].fd != -1)
        {
            delete subprocsockets[i];
        }
    }
    delete[]subprocspids;
    delete[]subprocsstates;
    delete[]subprocsrestart_cnt;
    delete[]subprocsockets;
    delete[]pids;  // 4 deletes good, memory leaks bad
    //delete dystat;
}

String readymess2("2\n");
String readymess3("3\n");

// send Ready signal to parent process over the socketpair (used in handle_connections)
int send_readystatus(UDSocket &pipe, String *message)  				// blocks until timeout
{
//	String message("2\n");d
    try
    {
        if (!pipe.writeToSocket((*message).toCharArray(), (*message).length(), 0, 15, true, true))
        {
            return -1;
        }
    }
    catch (std::exception & e)
    {
        return -1;
    }
    return 0;
}

// handle any connections received by this subproc (also tell parent we're ready each time we become idle)
int handle_connections(UDSocket &pipe)
{
    ConnectionHandler h;  // the class that handles the connections
    String ip;
    bool toldparentready = false;
    int cycle = o.maxage_subprocs;
    int stat = 0;
    int rc = 0;
    String *mess_no = &readymess2;
    reloadconfig = false;

    // stay alive both for the maximum allowed age of subproc processes, and whilst we aren't supposed to be re-reading configuration
    while (cycle-- && !reloadconfig)
    {
        if (!toldparentready)
        {
            if (send_readystatus(pipe, mess_no ) == -1)  	// non-blocking (timed)
            {
#ifdef DGDEBUG
                std::cout << "parent timed out telling it we're ready" << std::endl;
#endif
                break;  // parent timed out telling it we're ready
                // so either parent gone or problem so lets exit this joint
            }
            toldparentready = true;
        }

        if (!getsock_fromparent(pipe))  	// blocks waiting for a few mins
        {
            continue;
        }
        toldparentready = false;

		//Check the ecap peer connection
		if(ecappeer->getFD() < 0){
			if (o.logconerror){
                syslog(LOG_INFO, "Error accepting. (Ignorable)");
			}
            continue;
		}

		if(connectiontype == ConnectionType::ECAP_REQMOD){
			rc = h.handleEcapReqmod(*ecappeer);
		} else{
			rc = h.handleEcapRespmod(*ecappeer);
		}

        if (rc == 3){
            mess_no = &readymess3;
        }
        else{
            mess_no = &readymess2;
        }
        delete ecappeer;
    }
    if (!(++cycle) && o.logsubprocs)
        syslog(LOG_ERR, "subproc has handled %d requests and is exiting", o.maxage_subprocs);
#ifdef DGDEBUG
    if (reloadconfig)
    {
        std::cout << "subproc been told to exit by hup" << std::endl;
    }
#endif
    if (!toldparentready)
    {
        stat = 2;
    }
    return stat;
}

// the parent process recieves connections - subprocs receive notifications of this over their socketpair, and accept() them for handling
bool getsock_fromparent(UDSocket &fd)
{
    String message;
    char buf;
    int rc;
    try
    {
        rc = fd.readFromSocket(&buf, 1, 0, 360, true, true);  // blocks for a few mins
    }
    catch (std::exception & e)
    {
        // whoop! we received a SIGHUP. we should reload our configuration - and no, we didn't get an FD.
        reloadconfig = true;
        return false;
    }

    // check the message from the parent
    if (rc < 1)
    {
        return false;
    }
	//The index received here will be either 0 or 1 at the moment
	//0 is REQMOD, 1 is RESPMOD
	if(buf == 0){
		//REQMOD
		connectiontype = ConnectionType::ECAP_REQMOD;
		ecappeer = ecapreqlistener.accept();
#ifdef DGDEBUG
    std::cout << "subproc accepting REQMOD socket " << buf << std::endl;
#endif
	} else if (buf == 1){
		//RESPMOD
		connectiontype = ConnectionType::ECAP_RESPMOD;
		ecappeer = ecapresplistener.accept();
#ifdef DGDEBUG
    std::cout << "subproc accepting RESPMOD socket " << buf << std::endl;
#endif
	} else{
		//What's this?
#ifdef DGDEBUG
    std::cout << "subproc not accepting unknown socket " << buf << std::endl;
#endif
		return false;
	}

    try
    {
        fd.writeToSockete("K", 1, 0, 10, true);  // need to make parent wait for OK
        // so effectively providing a lock
    }
    catch (std::exception & e)
    {
        if (o.logconerror){
            syslog(LOG_ERR, "Error telling parent we accepted: %s", e.what());
		}
        ecappeer->close();
        return false;
    }

    return true;
}

// *
// *
// * end of subproc process code
// *
// *

// *
// *
// * start of subproc process handling (minus prefork)
// *
// *

void tell_monitor(bool active)
{

    String buff(o.monitor_helper);
    String buff1;

    if (active)
        buff1 = " start";
    else
        buff1 = " stop";

    syslog(LOG_ERR, "Proxy not responding, monitorhelper : %s%s", buff.c_str(), buff1.c_str() );

    int systemreturn = execl(buff.c_str(), buff1.c_str(), NULL);
    if ( systemreturn == -1)
        syslog(LOG_ERR, "Something wrong with: %s%s : errno %s", buff.c_str(), buff1.c_str(), strerror(errno));
    return;
};

void wait_for_proxy()
{
    Socket proxysock;
    int rc;

    try
    {
        // ...connect to proxy
        rc = proxysock.connect(o.proxy_ip, o.proxy_port);
        if (!rc)
        {
            proxysock.close();
            cache_erroring = 0;
            return;
        }
        syslog(LOG_ERR, "Proxy is not responding - Waiting for proxy to respond");
        if (o.monitor_helper_flag) tell_monitor(false);
        int wait_time = 1;
        // why 10 mins ?
        // int interval = 600; // 10 mins

        int interval = o.proxy_timeout;
        int cnt_down = interval;
        while (true)
        {
            rc = proxysock.connect(o.proxy_ip, o.proxy_port);
            if (!rc)
            {
                proxysock.close();
                cache_erroring = 0;
                syslog(LOG_ERR, "Proxy now responding - resuming after %d seconds", wait_time);
                if (o.monitor_helper_flag) tell_monitor(true);
                return;
            }
            else
            {
                wait_time++;
                cnt_down--;
                if (cnt_down < 1)
                {
                    syslog(LOG_ERR, "Proxy not responding - still waiting after %d seconds proxytimeout = %d",  wait_time, interval);
                    cnt_down = interval;
                }
                sleep(1);
            }
        }
    }
    catch (std::exception & e)
    {
#ifdef DGDEBUG
        std::cerr << " -exception while creating proxysock: " << e.what() << std::endl;
#endif
    }
}

// look for any dead subprocs, and clean them up
void mopup_aftersubprocs()
{
    pid_t pid;
    int stat_val;
    while (true)
    {
        pid = waitpid(-1, &stat_val, WNOHANG);
        if (pid < 1)
        {
            break;
        }
#ifdef DGDEBUG
        if (WIFEXITED(stat_val))
        {
            std::cout << "subproc " << pid << " exited with status " << WEXITSTATUS(stat_val) << std::endl;
        }
        else
        {
            if (WIFSIGNALED(stat_val))
            {
                std::cout << "subproc " << pid << " exited on signal " << WTERMSIG(stat_val) << std::endl;
            }
        };

        std::cout << "mopup deleting subproc" << pid  << std::endl;
#endif
        deletesubproc((int) pid);
        dystat->deaths++;
    }
}

// get a free slot in out PID list, if there is one - return -1 if not
int getsubprocslot()
{
    int i;
    for (i = 0; i < o.max_subprocs; i++)
    {
        if (subprocspids[i] == -1)
        {
            return i;
        }
    }
    return -1;
}

// add the given subproc, including FD & PID, to the given slot in our lists
void addsubproc(int pos, int fd, pid_t subproc_pid)
{
    if (pos < 0){
        return;
	}
    numsubprocs++;
    busysubprocs++;
    waitingfor++;

    subprocspids[pos] = (int) subproc_pid;
    subprocsstates[pos] = 4;  // busy waiting for init
    subprocsrestart_cnt[pos] = restart_cnt;
    pids[pos].fd = fd;
    UDSocket* sock = new UDSocket(fd);
    subprocsockets[pos] = sock;
#ifdef DGDEBUG
    std::cout << "added subproc:" << fd << ":" << subprocspids[fd] << std::endl;
#endif
    if (o.logsubprocs){
        syslog(LOG_ERR, "added subproc: fd: %d pid: %d", fd, subproc_pid);
	}
}

// kill give number of non-busy subprocs
void cullsubprocs(int num)
{
#ifdef DGDEBUG
    std::cout << "culling subprocs:" << num << std::endl;
#endif
    int i;
    int count = 0;
    for (i = top_subproc_fds - 1; i >= 0; i--)
    {
        if (subprocsstates[i] == 0)
        {
            kill(subprocspids[i], SIGTERM);
            count++;
            subprocsstates[i] = -2;  // dieing
            freesubprocs--;
            deletesubproc_by_fd(i);
            if (count >= num)
            {
                break;
            }
        }
    }
}

// send SIGTERM to all subproc processes
void kill_allsubprocs()
{
#ifdef DGDEBUG
    std::cout << "killing all subprocs:" << std::endl;
#endif
    for (int i = top_subproc_fds - 1; i >= 0; i--)
    {
        if (subprocsstates[i] >= 0)
        {
            kill(subprocspids[i], SIGTERM);
            subprocsstates[i] = -2;  // dieing
            numsubprocs--;
            delete subprocsockets[i];
            subprocsockets[i] = NULL;
            pids[i].fd = -1;
        }
    }
}

// send SIGHUP to all subproc processes
void hup_allsubprocs()
{
#ifdef DGDEBUG
    std::cout << "huping all subprocs:" << std::endl;
#endif
    for (int i = top_subproc_fds - 1; i >= 0; i--)
    {
        if (subprocsstates[i] >= 0)
        {
            kill(subprocspids[i], SIGHUP);
        }
    }
}

// send SIGHUP to some subproc processes used in gentle restart
void hup_somesubprocs(int num, int start)
{
#ifdef DGDEBUG
    std::cout << "huping some subprocs:" << std::endl;
#endif
    hup_index = start;
    int count = 0;
    for (int i = start; i < top_subproc_fds; i++)
    {


        if ((subprocsstates[i] >= 0) && (subprocsrestart_cnt[i] != restart_cnt) )   // only kill subprocs started before last gentle
        {
            if (subprocsstates[i] == 0 )    // subproc is free - might as well SIGTERM
            {
                subprocsstates[i] = -2;
                kill(subprocspids[i], SIGTERM);
                freesubprocs--;
                deletesubproc_by_fd(i);
            }
            else
            {
                subprocsstates[i] = 2;
                kill(subprocspids[i], SIGHUP);
            }
            count++;
            if (count >= num )
            {
                break;
            }
        }
        hup_index++;
    }
    gentle_to_hup -= count;
}

// attempt to receive the message from the subproc's send_readystatus call
bool check_subproc_readystatus(int tofind)
{
    bool found = false;
    char *buf = new char[5];
    int rc = -1;  // for compiler warnings
    for (int f = 0; f < o.max_subprocs; f++)
    {
        if (tofind < 1)
        {
            break;  // no point looping through all if all found
        }
        if (pids[f].fd == -1)
        {
            continue;
        }
        if ((pids[f].revents & POLLIN) > 0)
        {
            if (subprocsstates[f] < 0)
            {
//				tofind--;  // this may be an error!!!!
                continue;
            }
            try
            {
                rc = subprocsockets[f]->getLine(buf, 4, 100, true);
            }
            catch (std::exception & e)
            {
                kill(subprocspids[f], SIGTERM);
                deletesubproc_by_fd(f);
//				tofind--;  // this may be an error!!!!
                continue;
            }
            if (rc > 0)
            {
                if (buf[0] == '2')
                {
                    if (subprocsstates[f] == 4)
                    {
                        waitingfor--;
                    }
                    subprocsstates[f] = 0;
                    busysubprocs--;
                    freesubprocs++;
//					tofind--; // this may be an error!!!!
                }
                else if (buf[0] == '3')      //cache comms error
                {
                    if (subprocsstates[f] == 4)
                    {
                        waitingfor--;
                    }
                    subprocsstates[f] = 0;
                    busysubprocs--;
                    freesubprocs++;
                    cache_erroring++;
                }
            }
            else  	// subproc -> parent communications failure so kill it
            {
                kill(subprocspids[f], SIGTERM);
                deletesubproc_by_fd(f);
//				tofind--;// this may be an error!!!!
            }
        }
        if (subprocsstates[f] == 0)
        {
            found = true;
        }
        else
        {
            found = false;
        }
    }
    // if unbusy found then true otherwise false
    delete[]buf;
    return found;
}

void deletesubproc_by_fd(int i)
{
    subprocspids[i] = -1;
    // Delete a busy subproc
    if (subprocsstates[i] == 1 || subprocsstates[i] == 2)
        busysubprocs--;
    // Delete a subproc which isn't "ready" yet
    if (subprocsstates[i] == 4)
    {
        busysubprocs--;
        waitingfor--;
    }
    // Delete a free subproc
    if (subprocsstates[i] == 0)
        freesubprocs--;
    // Common code for any non-"culled" subproc
//			if (subprocsstates[i] != -2) {
    // common code for all subprocs
    if (true)
    {
        numsubprocs--;
        delete subprocsockets[i];
        subprocsockets[i] = NULL;
        pids[i].fd = -1;
    }
    subprocsstates[i] = -1;  // unused
}

void reset_subprocstats()
{
    int i;
    busysubprocs = 0;
    numsubprocs = 0;
    freesubprocs = 0;
    waitingfor = 0;
    for (i = 0; i < top_subproc_fds; i++)
    {
        if (subprocsstates[i] == 1 || subprocsstates[i] == 2)
            busysubprocs++;
        if (subprocsstates[i] == 4)
        {
            busysubprocs++;
            waitingfor++;
        }
        if (subprocsstates[i] == 0)
            freesubprocs++;
        if (subprocsstates[i] > -1)
            numsubprocs++;
    }
};

// remove subproc from our PID/FD and slot lists
void deletesubproc(int subproc_pid)
{
    int i;
    for (i = 0; i < top_subproc_fds; i++)
    {
        if (subprocspids[i] == subproc_pid)
        {
            deletesubproc_by_fd(i);
            break;
        }
    }
    // never should happen that passed pid is not known,
    // unless its the logger or url cache process, in which case we
    // don't want to do anything anyway. and this can only happen
    // when shutting down or restarting.
}

// get the index of the first non-busy subproc
int getfreesubproc()  				// check that there is 1 free done
{
    // before calling
    int i;
    for (i = 0; i < o.max_subprocs; i++)
    {
        if (subprocsstates[i] == 0)  	// not busy (free)
        {
            return i;
        }
    }
    return -1;
}

// tell given subproc process to accept an incoming connection
void tellsubproc_accept(int num, int whichsock)
{
    std::string sstr;
    sstr = whichsock;

    // include server socket number in message
    try
    {
#if DGDEBUG
        std::cout << "Telling subproc to accept socket " << whichsock << std::endl;
#endif
        subprocsockets[num]->writeToSockete(sstr.c_str(), 1, 0, 5, true);
    }
    catch (std::exception & e)
    {
        kill(subprocspids[num], SIGTERM);
        deletesubproc_by_fd(num);
        return;
    }

    // check for response from subproc
    char buf;
    try
    {
        subprocsockets[num]->readFromSocket(&buf, 1, 0, 5, false, true);
    }
    catch (std::exception & e)
    {
        kill(subprocspids[num], SIGTERM);
        deletesubproc_by_fd(num);
        return;
    }
    // no need to check what it actually contains,
    // as the very fact the subproc sent something back is a good sign
    busysubprocs++;
    freesubprocs--;
    dystat->conx++;
    subprocsstates[num] = 1;  // busy
}


// *
// *
// * end of subproc process handling code
// *
// *


// *
// *
// * logger, IP list and URL cache main loops
// *
// *

int log_listener(std::string log_location, bool logconerror, bool logsyslog)
{
#ifdef DGDEBUG
    std::cout << "log listener started" << std::endl;
#endif
    if (!drop_priv_completely())
    {
        return 1;  //error
    }
    o.deleteFilterGroupsJustListData();
    o.lm.garbageCollect();
    UDSocket* ipcpeersock;  // the socket which will contain the ipc connection
    int rc, ipcsockfd;

#ifdef ENABLE_EMAIL
    // Email notification patch by J. Gauthier
    std::map<std::string, int> violation_map;
    std::map<std::string, int> timestamp_map;
    std::map<std::string, std::string> vbody_map;

    int curv_tmp, stamp_tmp, byuser;
#endif

    //String where, what, how;
    std::string cr("\n");

    std::string where, what, how, cat, clienthost, from, who, mimetype, useragent, ssize, sweight, params, message_no;
    std::string stype, postdata;
    int port = 80, isnaughty = 0, isexception = 0, code = 200, naughtytype = 0;
    int cachehit = 0, wasinfected = 0, wasscanned = 0, filtergroup = 0;
    long tv_sec = 0, tv_usec = 0;
    int contentmodified = 0, urlmodified = 0, headermodified = 0;
    int headeradded = 0;

    std::ofstream* logfile = NULL;
    if (!logsyslog)
    {
        logfile = new std::ofstream(log_location.c_str(), std::ios::app);
        if (logfile->fail())
        {
            syslog(LOG_ERR, "Error opening/creating log file.");
#ifdef DGDEBUG
            std::cout << "Error opening/creating log file: " << log_location << std::endl;
#endif
            delete logfile;
            return 1;  // return with error
        }
    }

    ipcsockfd = loggersock.getFD();

    fd_set fdSet;  // our set of fds (only 1) that select monitors for us
    fd_set fdcpy;  // select modifies the set so we need to use a copy
    FD_ZERO(&fdSet);  // clear the set
    FD_SET(ipcsockfd, &fdSet);  // add ipcsock to the set


// Get server name - only needed for format 5
    String server("");
    if ( o.log_file_format == 5 )
    {
        char sysname[256];
        int r;
        r = gethostname(sysname, 256);
        if ( r == 0 )
        {
            server = sysname;
            server = server.before(".");
        }
    }

    std::string exception_word = o.language_list.getTranslation(51);
    exception_word = "*" + exception_word + "* ";
    std::string denied_word = o.language_list.getTranslation(52);
    denied_word = "*" + denied_word;
    std::string infected_word = o.language_list.getTranslation(53);
    infected_word =  "*" + infected_word + "* ";
    std::string scanned_word = o.language_list.getTranslation(54);
    scanned_word = "*" + scanned_word + "* ";
    std::string contentmod_word = o.language_list.getTranslation(55);
    contentmod_word = "*" + contentmod_word + "* ";
    std::string urlmod_word = o.language_list.getTranslation(56);
    urlmod_word = "*" + urlmod_word + "* ";
    std::string headermod_word = o.language_list.getTranslation(57);
    headermod_word = "*" + headermod_word + "* ";
    std::string headeradd_word = o.language_list.getTranslation(58);
    headeradd_word = "*" + headeradd_word + "* ";

    while (true)  		// loop, essentially, for ever
    {
        fdcpy = fdSet;  // take a copy
        rc = select(ipcsockfd + 1, &fdcpy, NULL, NULL, NULL);  // block

        // until something happens
        if (rc < 0)  	// was an error
        {
            if (errno == EINTR)
            {
                continue;  // was interupted by a signal so restart
            }
            if (logconerror)
            {
                syslog(LOG_ERR, "ipc rc<0. (Ignorable)");
            }
            continue;
        }
        if (rc < 1)
        {
            if (logconerror)
            {
                syslog(LOG_ERR, "ipc rc<1. (Ignorable)");
            }
            continue;
        }
        if (FD_ISSET(ipcsockfd, &fdcpy))
        {
#ifdef DGDEBUG
            std::cout << "received a log request" << std::endl;
#endif
            ipcpeersock = loggersock.accept();
            if (ipcpeersock->getFD() < 0)
            {
                delete ipcpeersock;
                if (logconerror)
                {
                    syslog(LOG_ERR, "Error accepting ipc. (Ignorable)");
                }
                continue;  // if the fd of the new socket < 0 there was error
                // but we ignore it as its not a problem
            }

            // Formatting code migration from ConnectionHandler
            // and email notification code based on patch provided
            // by J. Gauthier

            // read in the various parts of the log string
            bool error = false;
            int itemcount = 0;

            while (itemcount < 29)
            {
                try
                {
                    // Loop around reading in data, because we might have huge URLs
                    std::string logline;
                    char logbuff[8192];
                    bool truncated = false;
                    do
                    {
                        truncated = false;
                        rc = ipcpeersock->getLine(logbuff, 8192, 3, true, NULL, &truncated);  // throws on err
                        if (rc < 0)
                        {
                            delete ipcpeersock;
                            if (!is_daemonised)
                                std::cout << "Error reading from log socket" <<std::endl;
                            syslog(LOG_ERR, "Error reading from log socket");
                            error = true;
                            break;
                        }
                        if (rc == 0)
                            break;
                        // Limit overall item length, but we still need to
                        // read from the socket until next newline
                        if (logline.length() < 32768)
                            logline.append(logbuff, rc);
                    }
                    while (truncated);
                    if (error)
                        break;

                    switch (itemcount)
                    {
                    case 0:
                        isexception = atoi(logline.c_str());
                        break;
                    case 1:
                        cat = logline;
                        break;
                    case 2:
                        isnaughty = atoi(logline.c_str());
                        break;
                    case 3:
                        naughtytype = atoi(logline.c_str());
                        break;
                    case 4:
                        sweight = logline;
                        break;
                    case 5:
                        where = logline;
                        break;
                    case 6:
                        what = logline;
                        break;
                    case 7:
                        how = logline;
                        break;
                    case 8:
                        who = logline;
                        break;
                    case 9:
                        from = logline;
                        break;
                    case 10:
                        port = atoi(logline.c_str());
                        break;
                    case 11:
                        wasscanned = atoi(logline.c_str());
                        break;
                    case 12:
                        wasinfected = atoi(logline.c_str());
                        break;
                    case 13:
                        contentmodified = atoi(logline.c_str());
                        break;
                    case 14:
                        urlmodified = atoi(logline.c_str());
                        break;
                    case 15:
                        headermodified = atoi(logline.c_str());
                        break;
                    case 16:
                        ssize = logline;
                        break;
                    case 17:
                        filtergroup = atoi(logline.c_str());
                        break;
                    case 18:
                        code = atoi(logline.c_str());
                        break;
                    case 19:
                        cachehit = atoi(logline.c_str());
                        break;
                    case 20:
                        mimetype = logline;
                        break;
                    case 21:
                        tv_sec = atol(logline.c_str());
                        break;
                    case 22:
                        tv_usec = atol(logline.c_str());
                        break;
                    case 23:
                        clienthost = logline;
                        break;
                    case 24:
                        useragent = logline;
                        break;
                    case 25:
                        params = logline;
                        break;
                    case 26:
                        postdata = logline;
                        break;
                    case 27:
                        message_no = logline;
                        break;
                    case 28:
                        headeradded = atoi(logline.c_str());
                        break;
                    }
                }
                catch (std::exception & e)
                {
                    delete ipcpeersock;
                    if (logconerror)
                        syslog(LOG_ERR, "Error reading ipc. (Ignorable)");
                    error = true;
                    break;
                }
                itemcount++;
            }

            // don't build the log line if we couldn't read all the component parts
            if (error)
                continue;

            // Start building the log line

            if (port != 0 && port != 80)
            {
                // put port numbers of non-standard HTTP requests into the logged URL
                String newwhere(where);
                if (newwhere.after("://").contains("/"))
                {
                    String proto, host, path;
                    proto = newwhere.before("://");
                    host = newwhere.after("://");
                    path = host.after("/");
                    host = host.before("/");
                    newwhere = proto;
                    newwhere += "://";
                    newwhere += host;
                    newwhere += ":";
                    newwhere += String((int) port);
                    newwhere += "/";
                    newwhere += path;
                    where = newwhere;
                }
                else
                {
                    where += ":";
                    where += String((int) port);
                }
            }

            // stamp log entries so they stand out/can be searched
            switch (naughtytype)
            {
            case 1:
                stype = "-POST";
                break;
            case 2:
                stype = "-PARAMS";
                break;
            default:
                stype.clear();
            }
            if (isnaughty)
            {
                what = denied_word + stype + "* " + what;
            }
            else if (isexception && (o.log_exception_hits == 2))
            {
                what = exception_word + what;
            }

            if (wasinfected)
                what = infected_word + stype + "* " + what;
            else if (wasscanned)
                what = scanned_word + what;

            if (contentmodified)
            {
                what = contentmod_word + what;
            }
            if (urlmodified)
            {
                what = urlmod_word + what;
            }
            if (headermodified)
            {
                what = headermod_word + what;
            }
            if (headeradded)
            {
                what = headeradd_word + what;
            }

            std::string builtline, year, month, day, hour, min, sec, when, vbody, utime;
            struct timeval theend;

            // create a string representation of UNIX timestamp if desired
            if (o.log_timestamp || (o.log_file_format == 3)
                    || (o.log_file_format > 4))
            {
                gettimeofday(&theend, NULL);
                String temp((int) (theend.tv_usec / 1000));
                while (temp.length() < 3)
                {
                    temp = "0" + temp;
                }
                if (temp.length() > 3)
                {
                    temp = "999";
                }
                utime = temp;
                utime = "." + utime;
                utime = String((int) theend.tv_sec) + utime;
            }

            if (o.log_file_format != 3)
            {
                // "when" not used in format 3, and not if logging timestamps instead
                String temp;
                time_t tnow;  // to hold the result from time()
                struct tm *tmnow;  // to hold the result from localtime()
                time(&tnow);  // get the time after the lock so all entries in order
                tmnow = localtime(&tnow);  // convert to local time (BST, etc)
                year = String(tmnow->tm_year + 1900);
                month = String(tmnow->tm_mon + 1);
                day = String(tmnow->tm_mday);
                hour = String(tmnow->tm_hour);
                temp = String(tmnow->tm_min);
                if (temp.length() == 1)
                {
                    temp = "0" + temp;
                }
                min = temp;
                temp = String(tmnow->tm_sec);
                if (temp.length() == 1)
                {
                    temp = "0" + temp;
                }
                sec = temp;
                when = year + "." + month + "." + day + " " + hour + ":" + min + ":" + sec;
                // append timestamp if desired
                if (o.log_timestamp)
                    when += " " + utime;

            }


#ifdef NOTDEFINED
            // truncate long log items
            // moved to ConnectionHandler to avoid IPC overload
            // on very large URLs
            if (o.max_logitem_length > 0)
            {
                //where.limitLength(o.max_logitem_length);
                if (cat.length() > o.max_logitem_length)
                    cat.resize(o.max_logitem_length);
                if (what.length() > o.max_logitem_length)
                    what.resize(o.max_logitem_length);
                if (where.length() > o.max_logitem_length)
                    where.resize(o.max_logitem_length);
                /*if (who.length() > o.max_logitem_length)
                	who.resize(o.max_logitem_length);
                if (from.length() > o.max_logitem_length)
                	from.resize(o.max_logitem_length);
                if (how.length() > o.max_logitem_length)
                	how.resize(o.max_logitem_length);
                if (ssize.length() > o.max_logitem_length)
                	ssize.resize(o.max_logitem_length);*/
            }
#endif

            // blank out IP, hostname and username if desired
            if (o.anonymise_logs)
            {
                who = "";
                from = "0.0.0.0";
                clienthost.clear();
            }

            String stringcode(code);
            String stringgroup(filtergroup+1);

            switch (o.log_file_format)
            {
            case 4:
                builtline = when +"\t"+ who + "\t" + from + "\t" + where + "\t" + what + "\t" + how
                            + "\t" + ssize + "\t" + sweight + "\t" + cat +  "\t" + stringgroup + "\t"
                            + stringcode + "\t" + mimetype + "\t" + clienthost + "\t" + o.fg[filtergroup]->name
#ifdef SG_LOGFORMAT
                            + "\t" + useragent + "\t\t" + o.logid_1 + "\t" + o.prod_id + "\t"
                            + params + "\t" + o.logid_2 + "\t" + postdata;
#else
                            + "\t" + useragent + "\t" + params + "\t" + o.logid_1 + "\t" + o.logid_2 + "\t" + postdata;
#endif
                break;
            case 3:
            {
                // as certain bits of info are logged in format 3, their creation is best done here, not in all cases.
                std::string duration, hier, hitmiss;
                long durationsecs, durationusecs;
                durationsecs = (theend.tv_sec - tv_sec);
                durationusecs = theend.tv_usec - tv_usec;
                durationusecs = (durationusecs / 1000) + durationsecs * 1000;
                String temp((int) durationusecs);
                while (temp.length() < 6)
                {
                    temp = " " + temp;
                }
                duration = temp;

                if (code == 403)
                {
                    hitmiss = "TCP_DENIED/403";
                }
                else
                {
                    if (cachehit)
                    {
                        hitmiss = "TCP_HIT/";
                        hitmiss.append(stringcode);
                    }
                    else
                    {
                        hitmiss = "TCP_MISS/";
                        hitmiss.append(stringcode);
                    }
                }
                hier = "DEFAULT_PARENT/";
                hier += o.proxy_ip;

                /*if (o.max_logitem_length > 0) {
                	if (utime.length() > o.max_logitem_length)
                		utime.resize(o.max_logitem_length);
                	if (duration.length() > o.max_logitem_length)
                		duration.resize(o.max_logitem_length);
                	if (hier.length() > o.max_logitem_length)
                		hier.resize(o.max_logitem_length);
                	if (hitmiss.length() > o.max_logitem_length)
                		hitmiss.resize(o.max_logitem_length);
                }*/

                builtline = utime + " " + duration + " " + ( (clienthost.length() > 0) ? clienthost : from) + " " + hitmiss + " " + ssize + " "
                            + how + " " + where + " " + who + " " + hier + " " + mimetype;
                break;
            }
            case 2:
                builtline = "\"" + when  +"\",\""+ who + "\",\"" + from + "\",\"" + where + "\",\"" + what + "\",\""
                            + how + "\",\"" + ssize + "\",\"" + sweight + "\",\"" + cat +  "\",\"" + stringgroup + "\",\""
                            + stringcode + "\",\"" + mimetype + "\",\"" + clienthost + "\",\"" + o.fg[filtergroup]->name + "\",\""
                            + useragent + "\",\"" + params + "\",\"" + o.logid_1 + "\",\"" + o.logid_2 + "\",\"" + postdata + "\"";
                break;
            case 1:
                builtline = when +" "+ who + " " + from + " " + where + " " + what + " "
                            + how + " " + ssize + " " + sweight + " " + cat +  " " + stringgroup + " "
                            + stringcode + " " + mimetype + " " + clienthost + " " + o.fg[filtergroup]->name + " "
                            + useragent + " " + params + " " + o.logid_1 + " " + o.logid_2 + " " + postdata;
                break;
            case 5:
            case 6:
            default:
                std::string duration;
                long durationsecs, durationusecs;
                durationsecs = (theend.tv_sec - tv_sec);
                durationusecs = theend.tv_usec - tv_usec;
                durationusecs = (durationusecs / 1000) + durationsecs * 1000;
                String temp((int) durationusecs);
                duration = temp;

                builtline = utime + "\t"
                            + server + "\t"
                            + who + "\t"
                            + from + "\t"
                            + clienthost + "\t"
                            + where + "\t"
                            + how + "\t"
                            + stringcode + "\t"
                            + ssize + "\t"
                            + mimetype + "\t"
                            + (o.log_user_agent ? useragent : "-") + "\t"
                            + "-\t"   // squid result code
                            + duration + "\t"
                            + "-\t"   // squid peer code
                            + message_no + "\t"   // dg message no
                            + what + "\t"
                            + sweight + "\t"
                            + cat +  "\t"
                            + o.fg[filtergroup]->name + "\t"
                            + stringgroup ;
            }

            if (!logsyslog)
                *logfile << builtline << std::endl;  // append the line
            else
                syslog(LOG_INFO, "%s", builtline.c_str());
#ifdef DGDEBUG
            std::cout << itemcount << " " << builtline << std::endl;
#endif
            delete ipcpeersock;  // close the connection

#ifdef ENABLE_EMAIL
            // do the notification work here, but fork for speed
            if (o.fg[filtergroup]->use_smtp==true)
            {

                // run through the gambit to find out of we're sending notification
                // because if we're not.. then fork()ing is a waste of time.

                // virus
                if ((wasscanned && wasinfected) && (o.fg[filtergroup]->notifyav))
                {
                    // Use a double fork to ensure subproc processes are reaped adequately.
                    pid_t smtppid;
                    if ((smtppid = fork()) != 0)
                    {
                        // Parent immediately waits for first subproc
                        waitpid(smtppid, NULL, 0);
                    }
                    else
                    {
                        // First subproc forks off the *real* process, but immediately exits itself
                        if (fork() == 0)
                        {
                            // Second subproc - do stuff
                            setsid();
                            FILE* mail = popen (o.mailer.c_str(), "w");
                            if (mail==NULL)
                            {
                                syslog(LOG_ERR, "Unable to contact defined mailer.");
                            }
                            else
                            {
                                fprintf(mail, "To: %s\n", o.fg[filtergroup]->avadmin.c_str());
                                fprintf(mail, "From: %s\n", o.fg[filtergroup]->mailfrom.c_str());
                                fprintf(mail, "Subject: %s\n", o.fg[filtergroup]->avsubject.c_str());
                                fprintf(mail, "A virus was detected by e2guardian.\n\n");
                                fprintf(mail, "%-10s%s\n", "Data/Time:", when.c_str());
                                if (who != "-")
                                    fprintf(mail, "%-10s%s\n", "User:", who.c_str());
                                fprintf(mail, "%-10s%s (%s)\n", "From:", from.c_str(),  ((clienthost.length() > 0) ? clienthost.c_str() : "-"));
                                fprintf(mail, "%-10s%s\n", "Where:", where.c_str());
                                // specifically, the virus name comes after message 1100 ("Virus or bad content detected.")
                                String swhat(what);
                                fprintf(mail, "%-10s%s\n", "Why:", swhat.after(o.language_list.getTranslation(1100)).toCharArray() + 1);
                                fprintf(mail, "%-10s%s\n", "Method:", how.c_str());
                                fprintf(mail, "%-10s%s\n", "Size:", ssize.c_str());
                                fprintf(mail, "%-10s%s\n", "Weight:", sweight.c_str());
                                if (cat.c_str()!=NULL)
                                    fprintf(mail, "%-10s%s\n", "Category:", cat.c_str());
                                fprintf(mail, "%-10s%s\n", "Mime type:", mimetype.c_str());
                                fprintf(mail, "%-10s%s\n", "Group:", o.fg[filtergroup]->name.c_str());
                                fprintf(mail, "%-10s%s\n", "HTTP resp:", stringcode.c_str());

                                pclose(mail);
                            }
                            // Second subproc exits
                            _exit(0);
                        }
                        // First subproc exits
                        _exit(0);
                    }
                }

                // naughty OR virus
                else if ((isnaughty || (wasscanned && wasinfected)) && (o.fg[filtergroup]->notifycontent))
                {
                    byuser = o.fg[filtergroup]->byuser;

                    // if no violations so far by this user/group,
                    // reset threshold counters
                    if (byuser)
                    {
                        if (!violation_map[who])
                        {
                            // set the time of the first violation
                            timestamp_map[who] = time(0);
                            vbody_map[who] = "";
                        }
                    }
                    else if (!o.fg[filtergroup]->current_violations)
                    {
                        // set the time of the first violation
                        o.fg[filtergroup]->threshold_stamp = time(0);
                        o.fg[filtergroup]->violationbody="";
                    }

                    // increase per-user or per-group violation count
                    if (byuser)
                        violation_map[who]++;
                    else
                        o.fg[filtergroup]->current_violations++;

                    // construct email report
                    char *vbody_temp = new char[8192];
                    sprintf(vbody_temp, "%-10s%s\n", "Data/Time:", when.c_str());
                    vbody+=vbody_temp;

                    if ((!byuser) && (who != "-"))
                    {
                        sprintf(vbody_temp, "%-10s%s\n", "User:", who.c_str());
                        vbody+=vbody_temp;
                    }
                    sprintf(vbody_temp, "%-10s%s (%s)\n", "From:", from.c_str(),  ((clienthost.length() > 0) ? clienthost.c_str() : "-"));
                    vbody+=vbody_temp;
                    sprintf(vbody_temp, "%-10s%s\n", "Where:", where.c_str());
                    vbody+=vbody_temp;
                    sprintf(vbody_temp, "%-10s%s\n", "Why:", what.c_str());
                    vbody+=vbody_temp;
                    sprintf(vbody_temp, "%-10s%s\n", "Method:", how.c_str());
                    vbody+=vbody_temp;
                    sprintf(vbody_temp, "%-10s%s\n", "Size:", ssize.c_str());
                    vbody+=vbody_temp;
                    sprintf(vbody_temp, "%-10s%s\n", "Weight:", sweight.c_str());
                    vbody+=vbody_temp;
                    if (cat.c_str()!=NULL)
                    {
                        sprintf(vbody_temp, "%-10s%s\n", "Category:", cat.c_str());
                        vbody+=vbody_temp;
                    }
                    sprintf(vbody_temp, "%-10s%s\n", "Mime type:", mimetype.c_str());
                    vbody+=vbody_temp;
                    sprintf(vbody_temp, "%-10s%s\n", "Group:", o.fg[filtergroup]->name.c_str());
                    vbody+=vbody_temp;
                    sprintf(vbody_temp, "%-10s%s\n\n", "HTTP resp:", stringcode.c_str());
                    vbody+=vbody_temp;
                    delete[] vbody_temp;

                    // store the report with the group/user
                    if (byuser)
                    {
                        vbody_map[who]+=vbody;
                        curv_tmp = violation_map[who];
                        stamp_tmp = timestamp_map[who];
                    }
                    else
                    {
                        o.fg[filtergroup]->violationbody+=vbody;
                        curv_tmp = o.fg[filtergroup]->current_violations;
                        stamp_tmp = o.fg[filtergroup]->threshold_stamp;
                    }

                    // if threshold exceeded, send mail
                    if (curv_tmp >= o.fg[filtergroup]->violations)
                    {
                        if ((o.fg[filtergroup]->threshold == 0) || ( (time(0) - stamp_tmp) <= o.fg[filtergroup]->threshold))
                        {
                            // Use a double fork to ensure subproc processes are reaped adequately.
                            pid_t smtppid;
                            if ((smtppid = fork()) != 0)
                            {
                                // Parent immediately waits for first subproc
                                waitpid(smtppid, NULL, 0);
                            }
                            else
                            {
                                // First subproc forks off the *real* process, but immediately exits itself
                                if (fork() == 0)
                                {
                                    // Second subproc - do stuff
                                    setsid();
                                    FILE* mail = popen (o.mailer.c_str(), "w");
                                    if (mail==NULL)
                                    {
                                        syslog(LOG_ERR, "Unable to contact defined mailer.");
                                    }
                                    else
                                    {
                                        fprintf(mail, "To: %s\n", o.fg[filtergroup]->contentadmin.c_str());
                                        fprintf(mail, "From: %s\n", o.fg[filtergroup]->mailfrom.c_str());

                                        if (byuser)
                                            fprintf(mail, "Subject: %s (%s)\n", o.fg[filtergroup]->contentsubject.c_str(), who.c_str());
                                        else
                                            fprintf(mail, "Subject: %s\n", o.fg[filtergroup]->contentsubject.c_str());

                                        fprintf(mail, "%i violation%s ha%s occured within %i seconds.\n",
                                                curv_tmp,
                                                (curv_tmp==1)?"":"s",
                                                (curv_tmp==1)?"s":"ve",
                                                o.fg[filtergroup]->threshold);

                                        fprintf(mail, "%s\n\n", "This exceeds the notification threshold.");
                                        if (byuser)
                                            fprintf(mail, "%s", vbody_map[who].c_str());
                                        else
                                            fprintf(mail, "%s", o.fg[filtergroup]->violationbody.c_str());
                                        pclose(mail);
                                    }
                                    // Second subproc exits
                                    _exit(0);
                                }
                                // First subproc exits
                                _exit(0);
                            }
                        }
                        if (byuser)
                            violation_map[who]=0;
                        else
                            o.fg[filtergroup]->current_violations=0;
                    }
                } // end naughty OR virus
            } // end usesmtp
#endif

            continue;  // go back to listening
        }
    }
    // should never get here
    syslog(LOG_ERR, "%s", "Something wicked has ipc happened");

    if (logfile)
    {
        logfile->close();  // close the file
        delete logfile;
    }
    loggersock.close();
    return 1;  // It is only possible to reach here with an error
}


int url_list_listener(bool logconerror)
{
#ifdef DGDEBUG
    std::cout << "url listener started" << std::endl;
#endif
    if (!drop_priv_completely())
    {
        return 1;  //error
    }
    o.deleteFilterGroupsJustListData();
    o.lm.garbageCollect();
    UDSocket* ipcpeersock = NULL;  // the socket which will contain the ipc connection
    int rc, ipcsockfd;
    char *logline = new char[32000];
    char reply;
    DynamicURLList urllist;
#ifdef DGDEBUG
    std::cout << "setting url list size-age:" << o.url_cache_number << "-" << o.url_cache_age << std::endl;
#endif
    urllist.setListSize(o.url_cache_number, o.url_cache_age);
    ipcsockfd = urllistsock.getFD();
#ifdef DGDEBUG
    std::cout << "url ipcsockfd:" << ipcsockfd << std::endl;
#endif

    fd_set fdSet;  // our set of fds (only 1) that select monitors for us
    fd_set fdcpy;  // select modifes the set so we need to use a copy
    FD_ZERO(&fdSet);  // clear the set
    FD_SET(ipcsockfd, &fdSet);  // add ipcsock to the set

#ifdef DGDEBUG
    std::cout << "url listener entering select()" << std::endl;
#endif
    while (true)  		// loop, essentially, for ever
    {

        fdcpy = fdSet;  // take a copy

        rc = select(ipcsockfd + 1, &fdcpy, NULL, NULL, NULL);  // block
        // until something happens
#ifdef DGDEBUG
        std::cout << "url listener select returned" << std::endl;
#endif
        if (rc < 0)  	// was an error
        {
            if (errno == EINTR)
            {
                continue;  // was interupted by a signal so restart
            }
            if (logconerror)
            {
                syslog(LOG_ERR, "%s", "url ipc rc<0. (Ignorable)");
            }
            continue;
        }
        if (FD_ISSET(ipcsockfd, &fdcpy))
        {
#ifdef DGDEBUG
            std::cout << "received an url request" << std::endl;
#endif
            ipcpeersock = urllistsock.accept();
            if (ipcpeersock->getFD() < 0)
            {
                delete ipcpeersock;
                if (logconerror)
                {
#ifdef DGDEBUG
                    std::cout << "Error accepting url ipc. (Ignorable)" << std::endl;
#endif
                    syslog(LOG_ERR, "%s", "Error accepting url ipc. (Ignorable)");
                }
                continue;  // if the fd of the new socket < 0 there was error
                // but we ignore it as its not a problem
            }
            try
            {
                rc = ipcpeersock->getLine(logline, 32000, 3, true);  // throws on err
            }
            catch (std::exception & e)
            {
                delete ipcpeersock;  // close the connection
                if (logconerror)
                {
#ifdef DGDEBUG
                    std::cout << "Error reading url ipc. (Ignorable)" << std::endl;
                    std::cerr << e.what() << std::endl;
#endif
                    syslog(LOG_ERR, "%s", "Error reading url ipc. (Ignorable)");
                    syslog(LOG_ERR, "%s", e.what());
                }
                continue;
            }
            // check the command type
            // f: flush the cache
            // g: add a URL to the cache
            // everything else: search the cache
            // n.b. we use command characters with ASCII encoding
            // > 100, because we can have up to 99 filter groups, and
            // group no. plus 1 is the first character in the 'everything else'
            // case.
            if (logline[0] == 'f')
            {
                delete ipcpeersock;  // close the connection
                urllist.flush();
#ifdef DGDEBUG
                std::cout << "url FLUSH request" << std::endl;
#endif
                continue;
            }
            if (logline[0] == 'g')
            {
                delete ipcpeersock;  // close the connection
                urllist.addEntry(logline + 2, logline[1]-1);
                continue;
            }
            if (urllist.inURLList(logline + 1, logline[0]-1))
            {
                reply = 'Y';
            }
            else
            {
                reply = 'N';
            }
            try
            {
                ipcpeersock->writeToSockete(&reply, 1, 0, 6);
            }
            catch (std::exception & e)
            {
                delete ipcpeersock;  // close the connection
                if (logconerror)
                {
                    syslog(LOG_ERR, "%s", "Error writing url ipc. (Ignorable)");
                    syslog(LOG_ERR, "%s", e.what());
                }
                continue;
            }
            delete ipcpeersock;  // close the connection
#ifdef DGDEBUG
            std::cout << "url list reply: " << reply << std::endl;
#endif
            continue;  // go back to listening
        }
    }
    delete[]logline;
    urllistsock.close();  // be nice and neat
    return 1;  // It is only possible to reach here with an error
}

int ip_list_listener(std::string stat_location, bool logconerror)
{
#ifdef DGDEBUG
    std::cout << "ip listener started" << std::endl;
#endif
    if (!drop_priv_completely())
    {
        return 1;  //error
    }
    o.deleteFilterGroupsJustListData();
    o.lm.garbageCollect();
    UDSocket *ipcpeersock;
    int rc, ipcsockfd;
    char* inbuff = new char[16];

    // pass in size of list, and max. age of entries (7 days, apparently)
    DynamicIPList iplist(o.max_ips, 604799);

    ipcsockfd = iplistsock.getFD();

    unsigned long int ip;
    char reply;
    struct in_addr inaddr;

    struct timeval sleep;  // used later on for a short sleep
    sleep.tv_sec = 180;
    sleep.tv_usec = 0;
    struct timeval scopy;  // copy to use as select() can modify

    int maxusage = 0;  // usage statistics:
    // current & highest no. of concurrent IPs using the filter

    double elapsed = 0;  // keep a 3 minute counter so license statistics
    time_t before;   // are written even on busy networks (don't rely on timeout)

    fd_set fdSet;  // our set of fds (only 1) that select monitors for us
    fd_set fdcpy;  // select modifes the set so we need to use a copy
    FD_ZERO(&fdSet);  // clear the set
    FD_SET(ipcsockfd, &fdSet);  // add ipcsock to the set

#ifdef DGDEBUG
    std::cout << "ip listener entering select()" << std::endl;
#endif
    scopy = sleep;
    // loop, essentially, for ever
    while (true)
    {
        fdcpy = fdSet;  // take a copy
        before = time(NULL);
        rc = select(ipcsockfd + 1, &fdcpy, NULL, NULL, &scopy);  // block until something happens
        elapsed += difftime(time(NULL), before);
#ifdef DGDEBUG
        std::cout << "ip listener select returned: " << rc << ", 3 min timer: " << elapsed << ", scopy: " << scopy.tv_sec << " " << scopy.tv_usec << std::endl;
#endif
        if (rc < 0)    // was an error
        {
            if (errno == EINTR)
            {
                continue;  // was interupted by a signal so restart
            }
            if (logconerror)
            {
                syslog(LOG_ERR, "ip ipc rc<0. (Ignorable)");
            }
            continue;
        }
        if (rc == 0 || elapsed >= 180)
        {
#ifdef DGDEBUG
            std::cout << "ips in list: " << iplist.getNumberOfItems() << std::endl;
            std::cout << "purging old ip entries" << std::endl;
            std::cout << "ips in list: " << iplist.getNumberOfItems() << std::endl;
#endif
            // should only get here after a timeout
            iplist.purgeOldEntries();
            // write usage statistics
            int currusage = iplist.getNumberOfItems();
            if (currusage > maxusage)
                maxusage = currusage;
            String usagestats;
            usagestats += String(currusage) + "\n" + String(maxusage) + "\n";
#ifdef DGDEBUG
            std::cout << "writing usage stats: " << currusage << " " << maxusage << std::endl;
#endif
            int statfd = open(stat_location.c_str(), O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
            if (statfd > 0)
            {
                int dummy = write(statfd, usagestats.toCharArray(), usagestats.length());
            }
            close(statfd);
            // reset sleep timer
            scopy = sleep;
            elapsed = 0;
            // only skip back to top of loop if there was a genuine timeout
            if (rc == 0)
                continue;
        }
        if (FD_ISSET(ipcsockfd, &fdcpy))
        {
#ifdef DGDEBUG
            std::cout << "received an ip request" << std::endl;
#endif
            ipcpeersock = iplistsock.accept();
            if (ipcpeersock->getFD() < 0)
            {
                delete ipcpeersock;
                if (logconerror)
                {
#ifdef DGDEBUG
                    std::cout << "Error accepting ip ipc. (Ignorable)" << std::endl;
#endif
                    syslog(LOG_ERR, "Error accepting ip ipc. (Ignorable)");
                }
                continue; // if the fd of the new socket < 0 there was error
                // but we ignore it as its not a problem
            }
            try
            {
                rc = ipcpeersock->getLine(inbuff, 16, 3);  // throws on err
            }
            catch (std::exception& e)
            {
                delete ipcpeersock;
                if (logconerror)
                {
#ifdef DGDEBUG
                    std::cout << "Error reading ip ipc. (Ignorable)" << std::endl;
#endif
                    syslog(LOG_ERR, "Error reading ip ipc. (Ignorable)");
                }
                continue;
            }
#ifdef DGDEBUG
            std::cout << "recieved ip:" << inbuff << std::endl;
#endif
            inet_aton(inbuff, &inaddr);
            ip = inaddr.s_addr;
            // is the ip in our list? this also takes care of adding it if not.
            if (iplist.inList(ip))
                reply = 'Y';
            else
                reply = 'N';
            try
            {
                ipcpeersock->writeToSockete(&reply, 1, 0, 6);
            }
            catch (std::exception& e)
            {
                delete ipcpeersock;
                if (logconerror)
                {
#ifdef DGDEBUG
                    std::cout << "Error writing ip ipc. (Ignorable)" << std::endl;
#endif
                    syslog(LOG_ERR, "Error writing ip ipc. (Ignorable)");
                }
                continue;
            }
            delete ipcpeersock;  // close the connection
#ifdef DGDEBUG
            std::cout << "ip list reply: " << reply << std::endl;
#endif
            continue;  // go back to listening
        }
    }
    delete[] inbuff;
    iplistsock.close();  // be nice and neat
    return 1; // It is only possible to reach here with an error
}


// *
// *
// * end logger, IP list and URL cache code
// *
// *


// Does lots and lots of things - forks off url cache & logger processes, preforks subproc processes for connection handling, does tidying up on exit
// also handles the various signalling options DG supports (reload config, flush cache, kill all processes etc.)
int fc_controlit()
{
    int rc, fds;
    bool is_starting = true;

    o.lm.garbageCollect();

#ifdef DGDEBUG
    printf("Unlinking eCAP sockets\n");
#endif

    //Unlink the eCAP sockets
    unlink(o.ecap_reqmod_filename.c_str());
    unlink(o.ecap_respmod_filename.c_str());

#ifdef DGDEBUG
    printf("Binding to eCAP reqmod listener\n");
#endif

    //Bind to the eCAP sockets (tells them to listen later)
    if (ecapreqlistener.bind(o.ecap_reqmod_filename.c_str()))
    {
        if (!is_daemonised)
        {
            std::cerr << "Error binding ecapreqlistener server file (try using the SysV to stop e2guardian then try starting it again or doing an 'rm " << o.ecap_reqmod_filename << "')." << std::endl;
        }
        syslog(LOG_ERR, "Error binding ecapreqlistener server file (try using the SysV to stop e2guardian then try starting it again or doing an 'rm %s').", o.ecap_reqmod_filename.c_str());
        return 1;
    }

#ifdef DGDEBUG
    printf("Binding to eCAP reqmod listener\n");
#endif

    if (ecapresplistener.bind(o.ecap_respmod_filename.c_str()))
    {
        if (!is_daemonised)
        {
            std::cerr << "Error binding ecapresplistener server file (try using the SysV to stop e2guardian then try starting it again or doing an 'rm " << o.ecap_respmod_filename << "')." << std::endl;
        }
        syslog(LOG_ERR, "Error binding ecapresplistener server file (try using the SysV to stop e2guardian then try starting it again or doing an 'rm %s').", o.ecap_respmod_filename.c_str());
        return 1;
    }

    if (o.no_logger)
    {
        loggersock.close();
    }
    else
    {
        loggersock.reset();
    }
    if (o.url_cache_number > 0)
    {
        urllistsock.reset();
    }
    else
    {
        urllistsock.close();
    }
    if (o.max_ips > 0)
    {
        iplistsock.reset();
    }
    else
    {
        iplistsock.close();
    }

    pid_t loggerpid = 0;  // to hold the logging process pid
    pid_t urllistpid = 0;  // url cache process id
    pid_t iplistpid = 0; // ip cache process id

    if (!o.no_logger)
    {
        if (loggersock.getFD() < 0)
        {
            if (!is_daemonised)
            {
                std::cerr << "Error creating ipc socket" << std::endl;
            }
            syslog(LOG_ERR, "%s", "Error creating ipc socket");
            return 1;
        }
    }

    // Made unconditional such that we have root privs when creating pidfile & deleting old IPC sockets
    // PRA 10-10-2005
	
#ifdef DGDEBUG
    std::cout << "seteuiding for low port binding/pidfile creation" << std::endl;
#endif

#ifdef HAVE_SETREUID
    rc = setreuid((uid_t) - 1, o.root_user);
#else
    rc = seteuid(o.root_user);
#endif
    if (rc == -1)
    {
        syslog(LOG_ERR, "%s", "Unable to seteuid() to bind filter port.");
#ifdef DGDEBUG
        std::cerr << "Unable to seteuid() to bind filter port." << std::endl;
#endif
        return 1;
    }

    // we have to open/create as root before drop privs
    int pidfilefd = sysv_openpidfile(o.pid_filename);
    if (pidfilefd < 0)
    {
        syslog(LOG_ERR, "%s", "Error creating/opening pid file.");
        std::cerr << "Error creating/opening pid file:" << o.pid_filename << std::endl;
        return 1;
    }

    // Made unconditional for same reasons as above
    //if (needdrop) {
#ifdef HAVE_SETREUID
    rc = setreuid((uid_t) - 1, o.proxy_user);
#else
    rc = seteuid(o.proxy_user);  // become low priv again
#endif
    if (rc == -1)
    {
        syslog(LOG_ERR, "Unable to re-seteuid()");
#ifdef DGDEBUG
        std::cerr << "Unable to re-seteuid()" << std::endl;
#endif
        close(pidfilefd);
        return 1;  // seteuid failed for some reason so exit with error
    }

    // Needs deleting if its there
    unlink(o.ipc_filename.c_str());  // this would normally be in a -r situation.
    // disabled as requested by Christopher Weimann <csw@k12hq.com>
    // Fri, 11 Feb 2005 15:42:28 -0500
    // re-enabled temporarily
    unlink(o.urlipc_filename.c_str());
    unlink(o.ipipc_filename.c_str());

    if (!o.no_logger)
    {
        if (loggersock.bind(o.ipc_filename.c_str()))  	// bind to file
        {
            if (!is_daemonised)
            {
                std::cerr << "Error binding ipc server file (try using the SysV to stop e2guardian then try starting it again or doing an 'rm " << o.ipc_filename << "')." << std::endl;
            }
            syslog(LOG_ERR, "Error binding ipc server file (try using the SysV to stop e2guardian then try starting it again or doing an 'rm %s').", o.ipc_filename.c_str());
            close(pidfilefd);
            return 1;
        }
        if (loggersock.listen(256))  	// set it to listen mode with a kernel
        {
            // queue of 256 backlog connections
            if (!is_daemonised)
            {
                std::cerr << "Error listening to ipc server file" << std::endl;
            }
            syslog(LOG_ERR, "Error listening to ipc server file");
            close(pidfilefd);
            return 1;
        }
    }

    if (o.url_cache_number > 0)
    {
        if (urllistsock.bind(o.urlipc_filename.c_str()))  	// bind to file
        {
            if (!is_daemonised)
            {
                std::cerr << "Error binding urllistsock server file (try using the SysV to stop e2guardian then try starting it again or doing an 'rm " << o.urlipc_filename << "')." << std::endl;
            }
            syslog(LOG_ERR, "Error binding urllistsock server file (try using the SysV to stop e2guardian then try starting it again or doing an 'rm %s').", o.urlipc_filename.c_str());
            close(pidfilefd);
            return 1;
        }
        if (urllistsock.listen(256))  	// set it to listen mode with a kernel
        {
            // queue of 256 backlog connections
            if (!is_daemonised)
            {
                std::cerr << "Error listening to url ipc server file" << std::endl;
            }
            syslog(LOG_ERR, "Error listening to url ipc server file");
            close(pidfilefd);
            return 1;
        }
    }

    if (o.max_ips > 0)
    {
        if (iplistsock.bind(o.ipipc_filename.c_str()))  	// bind to file
        {
            if (!is_daemonised)
            {
                std::cerr << "Error binding iplistsock server file (try using the SysV to stop e2guardian then try starting it again or doing an 'rm " << o.ipipc_filename << "')." << std::endl;
            }
            syslog(LOG_ERR, "Error binding iplistsock server file (try using the SysV to stop e2guardian then try starting it again or doing an 'rm %s').", o.ipipc_filename.c_str());
            close(pidfilefd);
            return 1;
        }
        if (iplistsock.listen(256))  	// set it to listen mode with a kernel
        {
            // queue of 256 backlog connections
            if (!is_daemonised)
            {
                std::cerr << "Error listening to ip ipc server file" << std::endl;
            }
            syslog(LOG_ERR, "Error listening to ip ipc server file");
            close(pidfilefd);
            return 1;
        }
    }

    //Tell the eCAP sockets to listen
    if (ecapreqlistener.listen(MAX_LISTEN))
    {
        // queue of MAX_LISTEN backlog connections, just like all the other sockets
        if (!is_daemonised)
        {
            std::cerr << "Error listening to eCAP REQMOD server file" << std::endl;
        }
        syslog(LOG_ERR, "Error listening to eCAP REQMOD server file");
        close(pidfilefd);
        return 1;
    }
    if (ecapresplistener.listen(MAX_LISTEN))
    {
        // queue of MAX_LISTEN backlog connections, just like all the other sockets
        if (!is_daemonised)
        {
            std::cerr << "Error listening to eCAP RESPMOD server file" << std::endl;
        }
        syslog(LOG_ERR, "Error listening to eCAP RESPMOD server file");
        close(pidfilefd);
        return 1;
    }

    if (!daemonise())
    {
        // detached daemon
        if (!is_daemonised)
        {
            std::cerr << "Error daemonising" << std::endl;
        }
        syslog(LOG_ERR, "Error daemonising");
        close(pidfilefd);
        return 1;
    }

    // this has to be done after daemonise to ensure we get the correct PID.
    rc = sysv_writepidfile(pidfilefd);  // also closes the fd
    if (rc != 0)
    {
        syslog(LOG_ERR, "Error writing to the e2guardian.pid file: %s", strerror(errno));
        return false;
    }
    // We are now a daemon so all errors need to go in the syslog, rather
    // than being reported on screen as we've detached from the console and
    // trying to write to stdout will not be nice.

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL))  	// ignore SIGPIPE so we can handle
    {
        // premature disconections better
        syslog(LOG_ERR, "%s", "Error ignoring SIGPIPE");
        return (1);
    }
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGHUP, &sa, NULL))  	// ignore HUP
    {
        syslog(LOG_ERR, "%s", "Error ignoring HUP");
        return (1);
    }

    // Next thing we need to do is to split into two processes - one to
    // handle incoming TCP connections from the clients and one to handle
    // incoming UDS ipc from our forked subprocs.  This helps reduce
    // bottlenecks by not having only one select() loop.
    if (!o.no_logger)
    {
        loggerpid = fork();  // make a subproc processes copy of self to be logger

        if (loggerpid == 0)  	// ma ma!  i am the subproc
        {
            if (o.max_ips > 0)
            {
                iplistsock.close();
            }
            if (o.url_cache_number > 0)
            {
                urllistsock.close();  // we don't need our copy of this so close it
            }
            if ((log_listener(o.log_location, o.logconerror, o.log_syslog)) > 0)
            {
                syslog(LOG_ERR, "Error starting log listener");
            }
#ifdef DGDEBUG
            std::cout << "Log listener exiting" << std::endl;
#endif
            _exit(0);  // is reccomended for subproc and daemons to use this instead
        }
    }

    // Same for URL list listener
    if (o.url_cache_number > 0)
    {
        urllistpid = fork();
        if (urllistpid == 0)  	// ma ma!  i am the subproc
        {
            if (!o.no_logger)
            {
                loggersock.close();  // we don't need our copy of this so close it
            }
            if (o.max_ips > 0)
            {
                iplistsock.close();
            }
            if ((url_list_listener(o.logconerror)) > 0)
            {
                syslog(LOG_ERR, "Error starting url list listener");
            }
#ifdef DGDEBUG
            std::cout << "URL List listener exiting" << std::endl;
#endif
            _exit(0);  // is reccomended for subproc and daemons to use this instead
        }
    }

    // and for IP list listener
    if (o.max_ips > 0)
    {
        iplistpid = fork();
        if (iplistpid == 0)  	// ma ma!  i am the subproc
        {
            if (!o.no_logger)
            {
                loggersock.close();  // we don't need our copy of this so close it
            }
            if (o.url_cache_number > 0)
            {
                urllistsock.close();  // we don't need our copy of this so close it
            }
            if ((ip_list_listener(o.stat_location, o.logconerror)) > 0 )
            {
                syslog(LOG_ERR, "Error starting ip list listener");
            }
#ifdef DGDEBUG
            std::cout << "IP List listener exiting" << std::endl;
#endif
            _exit(0);  // is reccomended for subproc and daemons to use this instead
        }
    }

    // I am the parent process here onwards.

#ifdef DGDEBUG
    std::cout << "Parent process created subprocs" << std::endl;
#endif

    if (o.url_cache_number > 0)
    {
        urllistsock.close();  // we don't need our copy of this so close it
    }
    if (!o.no_logger)
    {
        loggersock.close();  // we don't need our copy of this so close it
    }
    if (o.max_ips > 0)
    {
        iplistsock.close();
    }

    memset(&sa, 0, sizeof(sa));
    if (!o.soft_restart)
    {
        sa.sa_handler = &sig_term;  // register sig_term as our handler
    }
    else
    {
        sa.sa_handler = &sig_termsafe;
    }
    if (sigaction(SIGTERM, &sa, NULL))  	// when the parent process gets a
    {
        // sigterm we need to kill our
        // subprocs which this will do,
        // then we need to exit
        syslog(LOG_ERR, "Error registering SIGTERM handler");
        return (1);
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = &sig_hup;  // register sig_hup as our handler
    if (sigaction(SIGHUP, &sa, NULL))  	// when the parent process gets a
    {
        // sighup we need to kill our
        // subprocs which this will do,
        // then we need to read config
        syslog(LOG_ERR, "Error registering SIGHUP handler");
        return (1);
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = &sig_usr1;  // register sig_usr1 as our handler
    if (sigaction(SIGUSR1, &sa, NULL))  	// when the parent process gets a
    {
        // sigusr1 we need to hup our
        // subprocs to make them exit
        // then we need to read fg config
        syslog(LOG_ERR, "Error registering SIGUSR handler");
        return (1);
    }

#ifdef ENABLE_SEGV_BACKTRACE
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = &sig_segv;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGSEGV, &sa, NULL))
    {
        syslog(LOG_ERR, "Error registering SIGSEGV handler");
        return 1;
    }
#endif

#ifdef DGDEBUG
    std::cout << "Parent process sig handlers done" << std::endl;
#endif

    numsubprocs = 0;  // to keep count of our subprocs
    busysubprocs = 0;  // to keep count of our subprocs
    freesubprocs = 0;  // to keep count of our subprocs

    subprocspids = new int[o.max_subprocs];  // so when one exits we know who
    subprocsstates = new int[o.max_subprocs];  // so we know what they're up to
    subprocsockets = new UDSocket* [o.max_subprocs];
    fds = o.max_subprocs + 2;  // +2 for the ecap sockets
    top_subproc_fds = o.max_subprocs;
    subprocsrestart_cnt = new int[o.max_subprocs];  // so we know what they're up to

    //
    //This is where you would add the extra two for eCAP req and resp mod
    //pids[0] will be reqmod
    //pids[1] will be respmod
    //
    pids = new struct pollfd[fds];
    int i;
    time_t tnow;
    time_t tmaxspare;
    time(&tmaxspare);

#ifdef DGDEBUG
    std::cout << "Parent process pid structs allocated" << std::endl;
#endif

    // store subproc fds...
    for (i = 0; i < top_subproc_fds; i++)
    {
        subprocspids[i] = -1;
        subprocsstates[i] = -1;
        subprocsockets[i] = NULL;
        subprocsrestart_cnt[i] = 0;
        pids[i].fd = -1;
        pids[i].events = POLLIN;
    }
	
    // ...and server fds
	// Note - unrolled loop here, as there are only ever two server sockets
    pids[(o.max_subprocs)].fd = ecapreqlistener.getFD();
    pids[(o.max_subprocs)].events = POLLIN;
    pids[(o.max_subprocs + 1)].fd = ecapresplistener.getFD();
    pids[(o.max_subprocs + 1)].events = POLLIN;

#ifdef DGDEBUG
    std::cout << "Parent process pid structs zeroed" << std::endl;
#endif

    failurecount = 0;  // as we don't exit on an error with select()
    // due to the fact that these errors do happen
    // every so often on a fully working, but busy
    // system, we just watch for too many errors
    // consecutivly.

    is_starting = true;
    waitingfor = 0;
    rc = prefork(o.min_subprocs);

    sleep(2);  // need to allow some of the forks to complete

#ifdef DGDEBUG
    std::cout << "Parent process preforked rc:" << rc << std::endl;
    std::cout << "Parent process pid:" << getpid() << std::endl;
#endif

    if (rc < 0)
    {
        ttg = true;
        syslog(LOG_ERR, "%s", "Error creating initial fork pool - exiting...");
    }

    int tofind;

    if (reloadconfig)
    {
        syslog(LOG_INFO, "Reconfiguring E2guardian: done");
    }
    else
    {
        syslog(LOG_INFO, "Started sucessfully.");
        //dystat = new stat_rec;
        dystat->start();
    }
    reloadconfig = false;

    wait_for_proxy(); // will return once a test connection established

    while (failurecount < 30 && !ttg && !reloadconfig)
    {

        // loop, essentially, for ever until 30
        // consecutive errors in which case something
        // is badly wrong.
        // OR, its timetogo - got a sigterm
        // OR, we need to exit to reread config
        if (gentlereload)
        {
#ifdef DGDEBUG
            std::cout << "gentle reload activated" << std::endl;
#endif
            syslog(LOG_INFO, "Reconfiguring E2guardian: gentle reload starting");
            o.deleteFilterGroups();
            if (!o.readFilterGroupConf())
            {
                reloadconfig = true;  // filter groups problem so lets
                // try and reload entire config instead
                // if that fails it will bomb out
            }
            else
            {
                if (o.use_filter_groups_list)
                {
                    o.filter_groups_list.reset();
                    if (!o.doReadItemList(o.filter_groups_list_location.c_str(),&(o.filter_groups_list),"filtergroupslist",true))
                        reloadconfig = true;  // filter groups problem...
                }
                if (!reloadconfig)
                {
                    o.deletePlugins(o.csplugins);
                    if (!o.loadCSPlugins())
                        reloadconfig = true;  // content scan plugs problem
                    if (!reloadconfig)
                    {
                        o.deletePlugins(o.authplugins);
                        if (!o.loadAuthPlugins())
                            reloadconfig = true;  // auth plugs problem
                    }
                    if (!reloadconfig)
                    {
                        o.deleteRooms();
                        o.loadRooms(false);
                        restart_cnt++;
                        if (restart_cnt > 32000 ) restart_cnt = 0;
                        int knum = o.gentle_chunk;
                        if (!gentle_in_progress)
                            restart_numsubprocs = numsubprocs;
                        gentle_to_hup = numsubprocs;
                        o.lm.garbageCollect();
                        //prefork(o.min_subprocs);
                        if (!gentle_in_progress)
                        {
                            if (o.logsubprocs)
                                syslog(LOG_ERR, "Spawning %d process(es) during gentle restart", o.gentle_chunk);
                            prefork(o.gentle_chunk);
                            //if (o.logsubprocs)
                            //syslog(LOG_ERR, "HUPing %d process(es) during gentle restart", knum);
                            //hup_somesubprocs(knum, 0);
                        }
                        next_gentle_check = time(NULL) + 5;

                        gentle_in_progress = true;
                        gentlereload = false;
                        if (hup_index >= top_subproc_fds)
                        {
                            gentle_in_progress = false;
                            hup_index = 0;
                            syslog(LOG_INFO, "Reconfiguring E2guardian: gentle reload completed");
                        }

                        // everything ok - no full reload needed
                        // clear gentle reload flag for next run of the loop
                    }
                }
            }
            flush_urlcache();
            continue;
        }

        // Lets take the opportunity to clean up our dead subprocs if any
        if ( fds > FD_SETSIZE)
        {
            syslog(LOG_ERR, "Error polling subproc process sockets: You should reduce your maxsubprocs");
#ifdef DGDEBUG
            std::cout << "Error polling subproc process sockets: You should reduce your maxsubprocs" << std::endl;
#endif
            _exit(0);
        }
        else
        {
            for (i = 0; i < fds; i++)
            {
                pids[i].revents = 0;
            }
        }
        mopup_aftersubprocs();

        if (cache_erroring)
        {
            wait_for_proxy();
        }

        rc = poll(pids, fds, 60 * 1000);
        mopup_aftersubprocs();

        if (rc < 0)  	// was an error
        {
#ifdef DGDEBUG
            std::cout << "errno:" << errno << " " << strerror(errno) << std::endl;
#endif

            if (errno == EINTR)
            {
                continue;  // was interupted by a signal so restart
            }
            if (o.logconerror)
                syslog(LOG_ERR, "Error polling subproc process sockets: %s", strerror(errno));
            failurecount++;  // log the error/failure
            continue;  // then continue with the looping
        }

        tofind = rc;
        if (rc < 0)
        {
            for (i = o.max_subprocs; i < fds; i++)
            {
                if (pids[i].revents)
                {
                    tofind--;
                }
            }
        }

        if (tofind > 0)
        {
            check_subproc_readystatus(tofind);
            mopup_aftersubprocs();
        }

//		freesubprocs = numsubprocs - busysubprocs;
        if (freesubprocs != (numsubprocs - busysubprocs))
        {
            syslog(LOG_ERR, "freesubprocs %d + busysubprocs %d != numsubprocs %d", freesubprocs, busysubprocs, numsubprocs);
            reset_subprocstats();
            syslog(LOG_ERR, "stats reset to freesubprocs %d  busysubprocs %d numsubprocs %d", freesubprocs, busysubprocs, numsubprocs);
        }

#ifdef DGDEBUG
        std::cout << "numsubprocs:" << numsubprocs << std::endl;
        std::cout << "busysubprocs:" << busysubprocs << std::endl;
        std::cout << "freesubprocs:" << freesubprocs << std::endl;
        std::cout << "waitingfor:" << waitingfor << std::endl << std::endl;
#endif
		// Using the same polling code for all distros
		// Less work to maintain a single polling method, since we don't listen to more than
		// two server sockets at once
        if (rc > 0)
        {
            for (i = o.max_subprocs; i < fds; i++)
            {
                if ((pids[i].revents & POLLIN) > 0)
                {
                    // socket ready to accept() a connection
                    failurecount = 0;  // something is clearly working so reset count
                    if (freesubprocs < 1 && numsubprocs < o.max_subprocs)
                    {
                        if (waitingfor == 0)
                        {
                            //int num = o.prefork_subprocs;
                            //	if ((o.max_subprocs - numsubprocs) < num)
                            //		num = o.max_subprocs - numsubprocs;
                            //	if (o.logsubprocs)
                            //		syslog(LOG_ERR, "Under load - Spawning %d process(es)", num);
                            //	rc = prefork(num);
                            //	if (rc < 0) {
                            //		syslog(LOG_ERR, "Error forking %d extra process(es).", num);
                            //		failurecount++;
                            //	}
                        }// else
                        //	usleep(1000);
                        continue;
                    }
                    if (freesubprocs > 0)
                    {
#ifdef DGDEBUG
                        std::cout << "telling subproc to accept " << (i - o.max_subprocs) << std::endl;
#endif
                        int subprocnum = getfreesubproc();
                        if (subprocnum < 0)
                        {
                            // Oops! weren't actually any free subprocs.
                            // Not sure why as yet, but it seems this can
                            // sometimes happen. :(  PRA 2009-03-11
                            syslog(LOG_WARNING,
                                   "No free subprocs from getfreesubproc(): numsubprocs = %d, busysubprocs = %d, waitingfor = %d",
                                   numsubprocs, busysubprocs, waitingfor);
                            freesubprocs = 0;
                            usleep(1000);
                        }
                        else
                        {
#if DGDEBUG
                            std::cout << "Listen loop, telling subproc to accept socket " << i << std::endl;
#endif
                            tellsubproc_accept(subprocnum, i - o.max_subprocs);
                            --freesubprocs;
                        }
                    }
                    else
                    {
                        usleep(1000);
                    }
                }
                else if (pids[i].revents)
                {
                    ttg = true;
                    syslog(LOG_ERR, "Error with main listening socket.  Exiting.");
                    break;
                }
            }
            if (ttg)
                break;
        }
        if (is_starting)
        {
            if (o.monitor_helper_flag)
            {
                if (((numsubprocs - waitingfor) > o.monitor_start))
                {
                    tell_monitor(true);
                    is_starting = false;
                }
            }
            else
            {
                is_starting = false;
            }
        }

        time_t now = time(NULL);

        if (gentle_in_progress && (now > next_gentle_check) && (waitingfor == 0))
        {
            int fork_count = 0;
            int top_up = o.gentle_chunk;
            if (top_up > gentle_to_hup)
                top_up = gentle_to_hup;
            if (numsubprocs < (restart_numsubprocs + top_up )) // Attempt to restore numsubprocs to previous level asap
                fork_count = ((restart_numsubprocs + top_up ) - numsubprocs);
            if ((numsubprocs + fork_count) >= o.max_subprocs)
                fork_count = o.max_subprocs - numsubprocs;
            if (fork_count > 0)
            {
                if (o.logsubprocs)
                    syslog(LOG_ERR, "Spawning %d process(es) during gentle restart", fork_count);
                rc = prefork(fork_count);
                if (rc < 0)
                {
                    syslog(LOG_ERR, "Error forking %d extra processes during gentle restart", fork_count);
                    failurecount++;
                }
            }
            if (o.logsubprocs)
                syslog(LOG_ERR, "HUPing %d process(es) during gentle restart", top_up);
            hup_somesubprocs(top_up ,hup_index);
            if (hup_index >= top_subproc_fds)
            {
                gentle_in_progress = false;
                hup_index = 0;
                syslog(LOG_INFO, "Reconfiguring E2guardian: gentle reload completed");
            }
            next_gentle_check = time(NULL) + 5;
        }

        if (freesubprocs < o.minspare_subprocs && (waitingfor == 0) && numsubprocs < o.max_subprocs)
        {
            if (o.logsubprocs)
                syslog(LOG_ERR, "Fewer than %d free subprocs - Spawning %d process(es)", o.minspare_subprocs, o.prefork_subprocs);
            rc = prefork(o.prefork_subprocs);
            if (rc < 0)
            {
                syslog(LOG_ERR, "Error forking preforksubprocs extra processes.");
                failurecount++;
            }
        }
        if ( (waitingfor == 0) && (numsubprocs < o.min_subprocs))
        {
            int to_fork = o.prefork_subprocs;
            if ( to_fork > (o.min_subprocs - numsubprocs))
                to_fork = o.min_subprocs - numsubprocs;
            if (o.logsubprocs)
                syslog(LOG_ERR, "Fewer than %d subprocs - Spawning %d process(es)", o.min_subprocs, to_fork);
            rc = prefork(to_fork);
            if (rc < 0)
            {
                syslog(LOG_ERR, "Error forking %d extra processes.", to_fork);
                failurecount++;
            }
        }

        if (freesubprocs <= o.maxspare_subprocs)
        {
            time(&tmaxspare);
        }
        if (freesubprocs > o.maxspare_subprocs)
        {
            time(&tnow);
            if ((tnow - tmaxspare) > (2 * 60))
            {
                if (o.logsubprocs)
                    syslog(LOG_ERR, "More than %d free subprocs - Killing %d process(es)", o.maxspare_subprocs, freesubprocs - o.maxspare_subprocs);
                cullsubprocs(freesubprocs - o.maxspare_subprocs);
            }
        }
        if (o.dstat_log_flag && ( now >= dystat->end_int ))
            dystat->reset();
    }
    cullsubprocs(numsubprocs);  // remove the fork pool of spare subprocs

    for (int i = 0; i < o.max_subprocs; i++)
    {
        if (pids[i].fd != -1)
        {
            delete subprocsockets[i];
            subprocsockets[i] = NULL;
        }
    }
    if (numsubprocs > 0)
    {
        hup_allsubprocs();
        sleep(2);  // give them a small chance to exit nicely before we force
        // hmmmm I wonder if sleep() will get interupted by sigchlds?
    }
    if (numsubprocs > 0)
    {
        kill_allsubprocs();
    }
    // we might not giving enough time for defuncts to be created and then
    // mopped but on exit or reload config they'll get mopped up
    sleep(1);
    mopup_aftersubprocs();

    delete[]subprocspids;
    delete[]subprocsstates;
    delete[]subprocsockets;
    delete[]pids;  // 4 deletes good, memory leaks bad

    if (failurecount >= 30)
    {
        syslog(LOG_ERR, "%s", "Exiting due to high failure count.");
#ifdef DGDEBUG
        std::cout << "Exiting due to high failure count." << std::endl;
#endif
    }
#ifdef DGDEBUG
    std::cout << "Main parent process exiting." << std::endl;
#endif

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    if (sigaction(SIGTERM, &sa, NULL))  	// restore sig handler
    {
        // in subproc process
#ifdef DGDEBUG
        std::cerr << "Error resetting signal for SIGTERM" << std::endl;
#endif
        syslog(LOG_ERR, "%s", "Error resetting signal for SIGTERM");
    }
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGHUP, &sa, NULL))  	// restore sig handler
    {
        // in subproc process
#ifdef DGDEBUG
        std::cerr << "Error resetting signal for SIGHUP" << std::endl;
#endif
        syslog(LOG_ERR, "%s", "Error resetting signal for SIGHUP");
    }
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGUSR1, &sa, NULL))  	// restore sig handler
    {
        // in subproc process
#ifdef DGDEBUG
        std::cerr << "Error resetting signal for SIGUSR1" << std::endl;
#endif
        syslog(LOG_ERR, "%s", "Error resetting signal for SIGUSR1");
    }
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    if (sigaction(SIGPIPE, &sa, NULL))  	// restore sig handler
    {
        // in subproc process
#ifdef DGDEBUG
        std::cerr << "Error resetting signal for SIGPIPE" << std::endl;
#endif
        syslog(LOG_ERR, "%s", "Error resetting signal for SIGPIPE");
    }

    if (sig_term_killall)
    {
        struct sigaction sa, oldsa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = SIG_IGN;
        sigaction(SIGTERM, &sa, &oldsa);  // ignore sigterm for us
        kill(0, SIGTERM);  // send everyone in this process group a TERM
        // which causes them to exit as the default action
        // but it also seems to send itself a TERM
        // so we ignore it
        sigaction(SIGTERM, &oldsa, NULL);  // restore prev state
    }

    if (reloadconfig || ttg)
    {
        if (!o.no_logger)
            ::kill(loggerpid, SIGTERM);  // get rid of logger
        if (o.url_cache_number > 0)
            ::kill(urllistpid, SIGTERM);  // get rid of url cache
        if (o.max_ips > 0)
            ::kill(iplistpid, SIGTERM); // get rid of iplist
        return reloadconfig ? 2 : 0;
    }
    if (o.logconerror)
    {
        syslog(LOG_ERR, "%s", "Main parent process exiting.");
    }
    return 1;  // It is only possible to reach here with an error
}

