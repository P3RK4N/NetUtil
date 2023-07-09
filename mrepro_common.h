#ifndef MREPRO_COMMON_H
#define MREPRO_COMMON_H

/*  MREPRO_COMMON v0.4.2
*   All in one utility header for MREPRO exercises.
*
*   Currently features:
*       - all necessary includes in one place       
*       - some defines, typedefs, macros for ease of use
*       - colored formatted multilevel (stdout and syslog abstracted) logging system
*       - demonization of process
*       - colored formatted asserts
*       - utility functions for networking and filesystem
*       - wrappers for various functions
*       - blocking listener for any kind of socket
*
*
*   *************
*   *** USAGE ***
*   *************
*
*   For each compile target(executable or library) do this in only ONE source file:
*
*   Before including header, define one of these
*       - MREPRO_COMMON_IMPL_DEBUG 
*       - MREPRO_COMMON_IMPL_RELEASE (omits logger functions)
*
*   Optionally define:
*       - MREPRO_MAX_PACKET_SIZE [4096]
*       - MREPRO_SOCKET_NUM_LISTEN [1024]
*       - MREPRO_MAX_URI_SIZE [200]
*       - MREPRO_MAX_HTTP_ATTRIBS [20]
*       - MREPRO_MAX_HTTP_ATTRIB_SIZE [200]
*/

/*
* 
* TODO fix read/write mess 
* TODO cleanup daemon and syslog mess
* 
*/


/*
*   ****************
*   *** INCLUDES ***
*   ****************
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <ctype.h>

#include <unistd.h>
#include <pthread.h>
#include <syslog.h>
#include <netdb.h>
#include <getopt.h>
#include <time.h>
#include <poll.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/*
*   ***************
*   *** DEFINES ***
*   ***************
*/

/* mrepro common -> mc */
#define MREPRO_COMMON_PREFIX mc

#ifndef MREPRO_MAX_PACKET_SIZE
    #define MREPRO_MAX_PACKET_SIZE 4096
#endif
#ifndef MREPRO_SOCKET_NUM_LISTEN
    #define MREPRO_SOCKET_NUM_LISTEN 1024
#endif
#ifndef MREPRO_MAX_HTTP_REQ_SIZE
    #define MREPRO_MAX_HTTP_REQ_SIZE 1024
#endif
#ifndef MREPRO_MAX_URI_SIZE
    #define MREPRO_MAX_URI_SIZE 200
#endif
#ifndef MREPRO_MAX_HTTP_ATTRIBS
    #define MREPRO_MAX_HTTP_ATTRIBS 20
#endif
#ifndef MREPRO_MAX_HTTP_ATTRIB_SIZE
    #define MREPRO_MAX_HTTP_ATTRIB_SIZE 200
#endif

/* Initialises an empty listener handle */
#define MREPRO_INIT_LISTENER_HANDLE(name) mcListenerHandle name = { 0, NULL };

typedef uint8_t             u8;
typedef uint8_t             byte;
typedef uint16_t            u16;
typedef uint32_t            u32;
typedef struct sockaddr     saddr;
typedef struct sockaddr_in  saddrin;
typedef struct sockaddr_in6 saddrin6;
typedef struct addrinfo     ainfo;
typedef struct timeval      tval;
typedef struct pollfd       pfd;
typedef struct sigaction    saction;

int         mcStatus    = 0;
bool        mcRunning   = 1;
const bool  mcTrue      = true;
const bool  mcFalse     = false;

/*
*   *******************************
*   *** MREPRO COMMON INTERFACE ***
*   *******************************
*/

/* DEBUGGING */

/* Log level. See mcSetLogLevel() for more info. */
typedef enum
{
    mcLogLevel_Debug = 0,
    mcLogLevel_Trace = 1,
    mcLogLevel_Info  = 2,
    mcLogLevel_Warn  = 3,
    mcLogLevel_Error = 4
} mcLogLevel_;

/* Sets minimum level which logger will output */
void        mcSetLogLevel(mcLogLevel_ lvl);
/* Sets logger title. Not required for logging. In case of daemon a new syslog is opened */
void        mcSetLogTitle(const char* title);

/* Debug level logger (GRAY) */
void        mcDebug(const char* fmt, ...);
/* Trace level logger (WHITE) */
void        mcTrace(const char* fmt, ...);
/* Info level logger (GREEN) */
void        mcInfo(const char* fmt, ...);
/* Warn level logger (YELLOW) */
void        mcWarn(const char* fmt, ...);
/* Error level logger. Outputs on stderr (RED) */
void        mcError(const char* fmt, ...);

/* Formatted assert function. Outputs on stderr (RED) */
void        mcAssert(bool check,const char* fmt, ...);


/* NETWORKING */

typedef struct _mcListenerHandle mcListenerHandle;

/* Function to which simple server dispatches current client */
typedef void(*mcSimpleServerDispatchFunc)(int sfd);
/* Function to which multiplexed listener dispatches event for this specific file descriptor */
typedef void(*mcListenerDispatchFunc)(int entryIndex, mcListenerHandle* listenerHandle);
/* Function to which multithreaded server dispatches clients */
typedef void*(*mcThreadDispatchFunc)(void* data);
/* Function to be called from poll server in case of timeout of all descriptors */
typedef void(*mcServerTimeoutFunc)(mcListenerHandle* mcListenerHandle);
/* Function for signal dispatching */
typedef void(*mcSignalDispatchFunc)(int sig);

typedef enum
{
    mcNetProtocol_None  = 0,
    mcNetProtocol_UDP   = IPPROTO_UDP,
    mcNetProtocol_TCP   = IPPROTO_TCP,
} mcNetProtocol_;

typedef enum
{
    mcNetFamily_None    = 0,
    mcNetFamily_4       = AF_INET,
    mcNetFamily_6       = AF_INET6,
} mcNetFamily_;

typedef enum
{
    mcHttpReq_None      = 0,
    mcHttpReq_GET       = 1,
    mcHttpReq_POST      = 2,
    mcHttpReq_HEAD      = 3,
    mcHttpReq_PUT       = 4,
    mcHttpReq_DELETE    = 5,
} mcHttpReq_;

typedef enum
{
    mcHttpVersion_None  = 0,
    mcHttpVersion_1_0   = 1,
    mcHttpVersion_1_1   = 2,
} mcHttpVersion_;

typedef enum
{
    mcHttpRes_None                  = 0,

    mcHttpRes_OK                    = 200,
    mcHttpRes_NoContent             = 204,

    mcHttpRes_MovedPermanently      = 301,

    mcHttpRes_BadRequest            = 400,
    mcHttpRes_NotAuthorized         = 401,
    mcHttpRes_NotFound              = 404,
    mcHttpRes_MethodNotAllowed      = 405,

    mcHttpRes_VersionNotSupported   = 505,
} mcHttpRes_;

typedef struct _mcHttpAttrib
{
    char name[30];
    char value[MREPRO_MAX_HTTP_ATTRIB_SIZE-30];
} mcHttpAttrib;

/* Holds info about http request. Must be initialised to 0 */
typedef struct _mcHttpReqInfo   // TODO make dynamic???
{
    mcHttpReq_ req;
    mcHttpVersion_ ver;
    char uri[MREPRO_MAX_URI_SIZE];
    mcHttpAttrib head[MREPRO_MAX_HTTP_ATTRIBS];
} mcHttpReqInfo;

/* Holds info about http response. Must be initialised to 0 */
typedef struct _mcHttpResInfo   // TODO make dynamic???
{
    mcHttpRes_ res;
    mcHttpVersion_ ver;
    mcHttpAttrib head[MREPRO_MAX_HTTP_ATTRIBS];
    int numAttribs;
    char* body;
} mcHttpResInfo;

/* Listener entry. It contains poll file descriptor, dispatch function and arbitrary data. */
typedef struct _mcListenerEntry
{
    pfd pollFD;
    mcListenerDispatchFunc func;
    void* data;
} mcListenerEntry;

/* Handle which we can poll with mcPollListener() or pass to mcRunPollServer(). It contains listener entries. */
typedef struct _mcListenerHandle
{
    int numEntries;
    mcListenerEntry* entries;
} mcListenerHandle;

/* Custom Listener which is used in poll/multiplexed server */

/* Reset multiplexed listener handle. This frees memory and closes all descriptors */
void        mcResetListenerHandle(mcListenerHandle* listenerHandle);
/* Appends new listenerEntry to listenerHandle */
void        mcAppendListenerEntry(mcListenerHandle* listenerHandle, mcListenerEntry* listenerEntry);
/* Creates new listenerEntry from fd to listenerHandle */
void        mcAppendListenerFD(mcListenerHandle* listenerHandle, int fd, mcListenerDispatchFunc func, void* data, int eventFlags);
/* Closes entry with this descriptor and removes it from descriptor array */
void        mcRemoveListenerFD(mcListenerHandle* listenerHandle, int fd);
/* Closes descriptor from pollFD and removes it from descriptor array */
void        mcRemoveListenerEntry(mcListenerHandle* listenerHandle, mcListenerEntry* listenerEntry);
/* Poll wrapper for manually polling listener handle */
int         mcPollListener(mcListenerHandle* listenerHandle, int timeout);
/* Runs on every descriptor of this listener */
void        mcListenerForEach(mcListenerHandle* listenerHandle, mcListenerDispatchFunc dispatchFunc);

/* Wrappers with error handling */

/* Wrapper for close() */
void        mcClose(int sfd);
/* Wrapper for connect() */
void        mcConnect(int sfd, saddr* addr, socklen_t addrLen);
/* Utility function for disconnection from UDP connections */
void        mcDisconnect(int sfd);
/* Wrapper for bind() */
void        mcBind(int sfd, saddr* addr, socklen_t addrLen);
/* Wrapper for listen() */
void        mcListen(int sfd, int numClients);
/* Wrapper for accept() */
int         mcAccept(int sfd, saddr* addr, socklen_t* addrLen);
/* Wrapper for setsockopt() */
void        mcSetSockOpt(int sfd, int level, int option, void* val);

/* UDP Recommened functions */

/* Wrapper for sendto(). Packet size is clamped to [0, MREPRO_MAX_PACKET_SIZE] */
int         mcSendTo(int sfd, const void* buffer, int n, int flags, saddr* addr, socklen_t addrLen);
/* Wrapper for sendto(). Can send arbitrary amount of data. Use if not connected */
ssize_t     mcSendNTo(int sfd, const void* buffer, size_t n, saddr* addr, socklen_t addrLen);
/* Wrapper for recvfrom(). Packet size is clamped to [0, MREPRO_MAX_PACKET_SIZE] */
int         mcRecvFrom(int sfd, void* buffer, int n, int flags, saddr* addr, socklen_t* addrLen);
/* Wrapper for recvfrom() with MSG_WAITALL. Can send arbitrary amount of data. Use if not connected */
ssize_t     mcRecvNFrom(int sfd, const void* buffer, size_t n, saddr* addr, socklen_t* addrLen);
/* Recvs into buffer until byte or until maximum size. Use if not connected */
ssize_t     mcRecvFromUntilByte(int sfd, const void* buffer, size_t maxSize, byte b, saddr* addr, socklen_t* addrLen);
/* TODO FIX Sends data from file pointer until the file EOF. Returns sent size in bytes. Use if not connected */
ssize_t     mcSendBinFileTo(int sfd, FILE* fp, saddr* addr, socklen_t addrLen);
/* TODO FIX Receives data and writes it to file pointer until socket EOF. Returns received size in bytes. Use if not connected */
ssize_t     mcRecvBinFileFrom(int sfd, FILE* fp, saddr* addr, socklen_t addrLen);

/* TCP Recommened functions */

/* Wrapper for read(). Use when connected. Not recommened for UDP connections */
ssize_t     mcReadN(int sfd, const void* buffer, size_t n);
/* Wrapper for write(). Use when connected. Not recommened for UDP connections */
ssize_t     mcWriteN(int sfd, const void* buffer, size_t n);
/* Reads into buffer until byte or until maximum size. Not recommened for UDP connections */
ssize_t     mcReadUntilByte(int sfd, const void* buffer, size_t maxSize, byte b);
/* Similar to mcReadUntilByte but this takes string and compares last strlen(word) bytes */
ssize_t     mcReadUntilWord(int sfd, const void* buffer, size_t maxSize, const char* word);
/* Sends data from file pointer until the file EOF. Returns sent size in bytes */
ssize_t     mcWriteBinFile(int sfd, FILE* fp);
/* Receives data and writes it to file pointer until socket EOF. Returns received size in bytes */
ssize_t     mcReadBinFile(int sfd, FILE* fp);

/* HTTP */

/* Get string representation from enum */
const char* mcHttpResStr(mcHttpRes_ res);
/* Get string representation from enum */
const char* mcHttpReqStr(mcHttpReq_ req);
/* Get string representation from enum */
const char* mcHttpVersionStr(mcHttpVersion_ ver);
/* Get string representation from enum */
mcHttpRes_  mcHttpResEnum(const char* res);
/* Get string representation from enum */
mcHttpReq_  mcHttpReqEnum(const char* req);
/* Get string representation from enum */
mcHttpVersion_ mcHttpVersionEnum(const char* ver);
/* Returns Content-Type html attribute from filename */
const char* mcGetContentTypeFromFilename(const char* filename); 
/* Print http request */
void mcPrintHttpReqInfo(mcHttpReqInfo* reqInfo);
/* Print http response*/
void mcPrintHttpResInfo(mcHttpResInfo* resInfo);
/* Appends new attribute to the response info. Do not mix with manual concatenation */
void mcAppendHttpAttribute(mcHttpResInfo* resInfo, const char* attribName, const char* attribVal);

/* Fill mcHttpReq struct with incoming data. If request was unsuccessful, it returns false. */
bool        mcParseHttpReq(int sfd, mcHttpReqInfo* reqInfo);
/* Send data from mcHttpRes */
void        mcSendHttpRes(int sfd, mcHttpResInfo* resInfo);

/* Utility function */

/* Returns string representation of address */
const char* mcIpNtoP(uint32_t netOrderAddr);
/* Returns string presentation of port */
const char* mcPortNtoP(short netOrderPort);
/* Creates addrinfo hints */
ainfo       mcAddrInfoHints(mcNetProtocol_ protocol, mcNetFamily_ family, bool passive);
/* Gets sockaddr from socket and fills localAddr. Returns addrLen */
socklen_t   mcGetSockLocalAddr(int sfd, saddr* localAddr);
/* Gets connected peer sockaddr from socket and fills peerAddr. Returns peerLen or 0 if not connected */
socklen_t   mcGetSockPeerAddr(int sfd, saddr* peerAddr);
/* Gets addrinfo based on name, service and hints */
ainfo*      mcGetAddrInfo(const char* name, const char* service, ainfo* hints);
/* Gets readable ip and port based on sockaddr. ip and port must be at least INET_ADDRSTRLEN6 and NI_MAXSERV bytes big */
void        mcGetNameInfo(saddr* addr, socklen_t addrLen, const char* ip, const char* port, int flags);
/* Returns string of network address in presentation format. Needs manual freeing of memory */
const char* mcGetAddrTxt(const saddr* addr);
/* Returns empty addr */
saddr       mcGetEmptyAddr();
/* Wrapper for socket creation */
int         mcSocket(mcNetProtocol_ protocol, mcNetFamily_ family);
/* Creates server socket. Starts listening on port */
int         mcServerSFD(const char* port, mcNetProtocol_ protocol, mcNetFamily_ family);
/* Creates client socket. Establishes connection to server with name and service */
int         mcClientSFDFromName(const char* serverName, const char* service, mcNetProtocol_ protocol, mcNetFamily_ family);
/* Creates client socket. Establishes connection to server with addr and addrlen */
int         mcClientSFDFromAddr(saddr* addr, socklen_t addrLen, mcNetProtocol_ protocol);
/* Starts simple server. TCP sfd needs to be set to listen before calling. Dispatches function once per client. Close it by setting mcRunning to false. Exiting will close all descriptors. */
void        mcRunSimpleServer(int sfd, mcSimpleServerDispatchFunc dispatchFunc);
/* Starts multiplexed server. Calls timeout function (if provided) on all descriptors upon timeout. Close it by setting mcRunning to false. Exiting will close all descriptors. */
void        mcRunPollServer(mcListenerHandle* listenerHandle, int timeout, mcServerTimeoutFunc timeoutFunc);


/* FILESYSTEM */

/* Check whether file exists */
bool        mcFileExists(const char* filename);
/* Check for read permission */
bool        mcIsFileR(const char* filename);
/* Check for write permission */
bool        mcIsFileW(const char* filename);
/* Check for read/write permissions */
bool        mcIsFileRW(const char* filename);
/* Wrapper for chdir */
void        mcChdir(const char* dir);
/* Returns file size in bytes without modifying pointer position */
ssize_t     mcGetFileBinSize(FILE* fp);
/* Gets file extension if exists, or "" otherwise */
const char* mcGetFileExtenstion(const char* filename);


/* THREADS | SIGNALS | DAEMONS */

/* Wrapper for daemon(). Starts syslog. All logging functions get directed to syslog */
void        mcDaemon(int nochdir, const char* logIndent, int logOption, int logFacility);
/* Wrapper for pthread_create() */
void        mcPthreadCreate(pthread_t* threadID, mcThreadDispatchFunc func, void* args);
/* Override function for handling signals. NOTE: before dispatching, mcRunning is set to false in case of SIGINT. You can enable it in your function if you want built in servers to keep running */
void        mcOverrideSignalDispatchFunc(int signum, mcSignalDispatchFunc func); ///TODO fix by nesting

/* MATH */

int         min(int a, int b);
int         max(int a, int b);
int         clamp(int value, int min, int max);

/*
*   **************************
*   *** MREPRO COMMON IMPL ***
*   **************************
*/

/*** Internal ***/
#if defined(MREPRO_COMMON_IMPL_DEBUG) || defined(MREPRO_COMMON_IMPL_RELEASE)

static char mcLogTitle[20] = {0};
static mcLogLevel_ mcLogLevel = mcLogLevel_Debug;

static bool mcDemonProcess  = false;
static int mcSyslogFacility = 0;
static int mcSyslogOption   = 0;

static char gray[]      = "\033[90m"; //DEBUG
static char white[]     = "\033[37m"; //TRACE
static char green[]     = "\033[32m"; //INFO
static char yellow[]    = "\033[33m"; //WARN
static char red[]       = "\033[31m"; //ERROR

static int mcLogLevelToSyslogLevel(mcLogLevel_ level)
{
    switch(level)
    {
        case mcLogLevel_Debug:  return LOG_DEBUG;
        case mcLogLevel_Trace:  return LOG_NOTICE;
        case mcLogLevel_Info:   return LOG_INFO;
        case mcLogLevel_Warn:   return LOG_WARNING;
        case mcLogLevel_Error:  return LOG_ERR;
        default: mcAssert(0, "Unknown mcLogLevel!");
    }
    return -1;
}

static inline void(setColorOut(const char* col)) { printf("%s", col); }
static inline void(setColorErr(const char* col)) { fprintf(stderr,"%s", col); }

static mcSignalDispatchFunc SigintDispatchFunc = NULL; 
static void mcSigintDispatchFuncWrapper(int sig) 
{ 
    mcRunning = false; 
    if(SigintDispatchFunc) SigintDispatchFunc(sig);
} 

#define CHECK_LOG_LEVEL(lvl)                                        \
    mcLogLevel_ logLevel = lvl;                                     \
    if(mcLogLevel > logLevel) return                                //TODO add prefix to macros
                                                                    //TODO fix dependency between macros
#define LOG(col)                                                    \
    va_list args;                                                   \
    va_start(args, fmt);                                            \
    if(!mcDemonProcess)                                             \
    {                                                               \
        setColorOut(col);                                           \
        printf("%s", mcLogTitle);                                   \
        vprintf(fmt, args);                                         \
        printf("\n");                                               \
        setColorOut(white);                                         \
        fflush(stdout);                                             \
    }                                                               \
    else                                                            \
    {                                                               \
        vsyslog(mcLogLevelToSyslogLevel(logLevel), fmt, args);      \
    }                                                                  

#endif //MREPRO_COMMON_IMPL_xxx

/*** Asserts ***/
#if defined(MREPRO_COMMON_IMPL_DEBUG) || defined(MREPRO_COMMON_IMPL_RELEASE)

void mcAssert(bool check, const char* fmt, ...)
{
    if(check) return;
    
    int er = errno;
    va_list args;
    va_start(args, fmt);
    
    char* fmtOut = (char*)calloc(100, 1);
    char* errOut = (char*)calloc(100,1);
    char* output = (char*)calloc(220, 1);

    vsprintf(fmtOut, fmt, args);
    er ? sprintf(errOut, "(%d -> %s)\n", er, strerror(er)) : sprintf(errOut, "\n");

    strcat(output, mcLogTitle); // Prefix - log name
    strcat(output, fmtOut);     // fmt body
    strcat(output, errOut);     // Suffix - errno + strerror

    if(!mcDemonProcess)
    {
        setColorErr(red);
        fprintf(stderr, "%s", output);
        fflush(stderr);
    }
    else
    {
        syslog(mcLogLevelToSyslogLevel(mcLogLevel_Error), "%s", output);
    }

    free(fmtOut);
    free(errOut);
    free(output);

    exit(EXIT_FAILURE);
}

#endif // MREPRO_COMMON_IMPL_xxx

/*** Logging ***/
#if defined(MREPRO_COMMON_IMPL_DEBUG)

    void mcDebug(const char* fmt, ...)    
    {
        CHECK_LOG_LEVEL(mcLogLevel_Debug);
        LOG(gray);
    }

    void mcTrace(const char* fmt, ...)
    {
        CHECK_LOG_LEVEL(mcLogLevel_Trace);
        LOG(white);
    }

    void mcInfo(const char* fmt, ...)
    {
        CHECK_LOG_LEVEL(mcLogLevel_Info);
        LOG(green);
    }

    void mcWarn(const char* fmt, ...)
    {
        CHECK_LOG_LEVEL(mcLogLevel_Warn);
        LOG(yellow);
    }

    void mcError(const char* fmt, ...)
    {
        CHECK_LOG_LEVEL(mcLogLevel_Error);
        LOG(red);
    }

    void mcSetLogTitle(const char* title) 
    {
        if(!mcDemonProcess)
        {
            u8 len = strlen(title);
            mcAssert(len <= 16, "Log title is too long: %d!", len);
            mcLogTitle[0] = '[';
            strncpy(mcLogTitle+1, title, len);
            strcpy(mcLogTitle+len+1, "] ");
        }
        else
        {
            mcLogTitle[0] = 0; //Disable regular log title TODO change?
            openlog(title, mcSyslogOption, mcSyslogFacility);
        }
    }

    void mcSetLogLevel(mcLogLevel_ level) { mcLogLevel = level; } // TODO make it change syslog level too?

#elif defined(MREPRO_COMMON_IMPL_RELEASE) //MREPRO_COMMON_IMPL_DEBUG

    inline void mcDebug(const char* fmt, ...)              {}
    inline void mcTrace(const char* fmt, ...)              {}
    inline void mcInfo(const char* fmt, ...)               {}
    inline void mcWarn(const char* fmt, ...)               {}
    inline void mcError(const char* fmt, ...)              {}

    inline void mcSetLogTitle(const char* title)           {}
    inline void mcSetLogLevel(mcLogLevel_ level)           {}

#endif //MREPRO_COMMON_IMPL_RELEASE

/*** Networking ***/
#if defined(MREPRO_COMMON_IMPL_DEBUG) || defined(MREPRO_COMMON_IMPL_RELEASE)

const char* mcHttpReqStr(mcHttpReq_ req)
{
    switch(req)
    {
        case mcHttpReq_GET:     return "GET";
        case mcHttpReq_POST:    return "POST";
        case mcHttpReq_HEAD:    return "HEAD";
        case mcHttpReq_PUT:     return "PUT";
        case mcHttpReq_DELETE:  return "DELETE";
        default: mcError("Unknown http request type!");
    }
    return (char*)NULL;
}

const char* mcHttpResStr(mcHttpRes_ res)
{
    switch(res)
    {
        case mcHttpRes_OK:                  return "200 OK";
        case mcHttpRes_NoContent:           return "204 No Content";
        case mcHttpRes_MovedPermanently:    return "301 Moved Permanently";
        case mcHttpRes_BadRequest:          return "400 Bad Request";
        case mcHttpRes_NotAuthorized:       return "401 Not Authorized";
        case mcHttpRes_NotFound:            return "404 Not Found";
        case mcHttpRes_MethodNotAllowed:    return "405 Method Not Allowed";
        case mcHttpRes_VersionNotSupported: return "505 HTTP Version Not Supported";
        default: mcError("Unknown http response type!");
    }
    return (char*)NULL;
}

const char* mcHttpVersionStr(mcHttpVersion_ ver)
{
    switch(ver)
    {
        case mcHttpVersion_1_0: return "HTTP/1.0";
        case mcHttpVersion_1_1: return "HTTP/1.1";
        default: mcError("Unknown http version!");
    }
    return (char*)NULL;
}

mcHttpReq_ mcHttpReqEnum(const char* req)
{
    if(!strcmp(req, "GET"))         return mcHttpReq_GET;
    else if(!strcmp(req, "POST"))   return mcHttpReq_POST;
    else if(!strcmp(req, "HEAD"))   return mcHttpReq_HEAD;
    else if(!strcmp(req, "PUT"))    return mcHttpReq_PUT;
    else if(!strcmp(req, "DELETE")) return mcHttpReq_DELETE;
    else mcError("Unknown http request type! %s", req);
    return mcHttpReq_HEAD; // TODO Not important
}

mcHttpRes_ mcHttpResEnum(const char* res)
{
    if(!strncmp(res, "200", 3))         return mcHttpRes_OK;
    if(!strncmp(res, "204", 3))         return mcHttpRes_NoContent;
    else if(!strncmp(res, "301", 3))    return mcHttpRes_MovedPermanently;
    else if(!strncmp(res, "400", 3))    return mcHttpRes_BadRequest;
    else if(!strncmp(res, "401", 3))    return mcHttpRes_NotAuthorized;
    else if(!strncmp(res, "404", 3))    return mcHttpRes_NotFound;
    else if(!strncmp(res, "405", 3))    return mcHttpRes_MethodNotAllowed;
    else if(!strncmp(res, "505", 3))    return mcHttpRes_VersionNotSupported;
    else mcError("Unknown http response type! %s", res);
    return mcHttpRes_MethodNotAllowed; //TODO change?
}

mcHttpVersion_ mcHttpVersionEnum(const char* ver)
{
    if(!strcmp(ver, "HTTP/1.0"))        return mcHttpVersion_1_0;
    else if(!strcmp(ver, "HTTP/1.1"))   return mcHttpVersion_1_1;
    else mcError(0, "Unknown http version! %s", ver);
    return mcHttpVersion_1_0; //TODO change?
}

const char* mcGetContentTypeFromFilename(const char* filename) 
{
    const char* extension = mcGetFileExtenstion(filename);
    if (strcmp(extension, "html") == 0 || strcmp(extension, "htm") == 0) {
        return "text/html";
    }
    else if (strcmp(extension, "txt") == 0) {
        return "text/plain";
    }
    else if (strcmp(extension, "css") == 0) {
        return "text/css";
    }
    else if (strcmp(extension, "js") == 0) {
        return "application/javascript";
    }
    else if (strcmp(extension, "jpg") == 0 || strcmp(extension, "jpeg") == 0) {
        return "image/jpeg";
    }
    else if (strcmp(extension, "gif") == 0) {
        return "image/gif";
    }
    else if (strcmp(extension, "png") == 0) {
        return "image/png";
    }
    else if (strcmp(extension, "pdf") == 0) {
        return "application/pdf";
    }
    else {
        return "application/octet-stream";
    }
}

void mcAppendHttpAttribute(mcHttpResInfo* resInfo, const char* attribName, const char* attribVal)
{
    mcAssert(resInfo->numAttribs < MREPRO_MAX_HTTP_ATTRIBS, "Reached attrib limit. Consider overriding MREPRO_MAX_HTTP_ATTRIBS before inclusion of header");
    strcpy(resInfo->head[resInfo->numAttribs].name, attribName);
    strcpy(resInfo->head[resInfo->numAttribs].value, attribVal);
}

bool mcParseHttpReq(int sfd, mcHttpReqInfo* reqInfo)
{
    char req[MREPRO_MAX_HTTP_REQ_SIZE];
    char* ptr = req;
    memset(req, 0, MREPRO_MAX_HTTP_REQ_SIZE);

    ssize_t amountRead = mcReadUntilWord(sfd, req, MREPRO_MAX_HTTP_REQ_SIZE, "\r\n\r\n");

    mcDebug("%s", req); //TODO remove?

    char reqType[10];
    char verType[10];
    sscanf(ptr, "%[^\x20] %[^\x20] %[^\r]", reqType, reqInfo->uri, verType);

    mcDebug("Req: %s", reqType);

    reqInfo->req = mcHttpReqEnum(reqType);
    reqInfo->ver = mcHttpVersionEnum(verType);

    while(*ptr != '\r' && (req+amountRead) != ptr) ptr++;
    if(req+amountRead == ptr) return false;
    else if(!strncmp("\r\n\r\n", ptr, 4)) return true;
    else ptr += 2;

    for(int i = 0; i < MREPRO_MAX_HTTP_ATTRIBS; i++)
    {
        sscanf(ptr, "%[^:]: %[^\r]", reqInfo->head[i].name, reqInfo->head[i].value);

        while(*ptr != '\r' && (req+amountRead) != ptr) ptr++;
        if(req+amountRead == ptr) return false;
        else if(!strncmp("\r\n\r\n", ptr, 4)) return true;
        else ptr += 2;
    }

    return true;
}

void mcSendHttpRes(int sfd, mcHttpResInfo* resInfo)
{
    const char clrf[] = "\r\n";
    
    char header[1024] = "";
    ssize_t fileSize = 0;

    strcat(header, mcHttpVersionStr(resInfo->ver));
    strcat(header, " ");
    strcat(header, mcHttpResStr(resInfo->res));
    strcat(header, clrf);

    for(int i = 0; i < MREPRO_MAX_HTTP_ATTRIBS; i++)
    {
        if(resInfo->head[i].name[0] == 0) break;
        strcat(header, resInfo->head[i].name);
        strcat(header, ": ");
        strcat(header, resInfo->head[i].value);
        strcat(header, clrf);

        if(!strcmp(resInfo->head[i].name, "Content-Length"))
        {
            sscanf(resInfo->head[i].value, "%ld", &fileSize);
        }
    }
    strcat(header, clrf);

    mcWriteN(sfd, header, strlen(header));
    mcWriteN(sfd, resInfo->body, fileSize);
}

void mcPrintHttpReqInfo(mcHttpReqInfo* reqInfo)
{
    mcInfo("HTTP Request Info:");
    mcTrace("Request Type: %s", mcHttpReqStr(reqInfo->req));
    mcTrace("Request Version: %s", mcHttpVersionStr(reqInfo->ver));
    mcTrace("Request URI: %s", reqInfo->uri);

    for(int i = 0; i < MREPRO_MAX_HTTP_ATTRIBS; i++)
    {
        if(reqInfo->head[i].name[0] == 0) break;
        mcTrace("Attribute => %s: %s", reqInfo->head[i].name, reqInfo->head[i].value);
    }
}

void mcPrintHttpResInfo(mcHttpResInfo* resInfo)
{
    mcInfo("HTTP Response Info:");
    mcTrace("Response Type: %s", mcHttpResStr(resInfo->res));
    mcTrace("Response Version: %s", mcHttpVersionStr(resInfo->ver));
    
    for(int i = 0; i < MREPRO_MAX_HTTP_ATTRIBS; i++)
    {
        if(resInfo->head[i].name[0] == 0) break;
        mcTrace("Attribute => %s: %s", resInfo->head[i].name, resInfo->head[i].value);
    }

    mcTrace("Response Body: %s", resInfo->body ? "Has data" : "Empty");
}

inline void mcClose(int sfd)                                        { mcAssert(close(sfd) != -1, "Socket close error!"); }
inline void mcConnect(int sfd, saddr* addr, socklen_t addrLen)      { mcAssert(connect(sfd, addr, addrLen) == 0, "Socket connect error!"); }
inline void mcBind(int sfd, saddr* addr, socklen_t addrLen)         { mcAssert(bind(sfd, addr, addrLen) == 0, "Server socket bind error!"); }
inline void mcListen(int sfd, int numClients)                       { mcAssert(listen(sfd, numClients) == 0, "Server socket listen error!"); }
inline void mcSetSockOpt(int sfd, int level, int option, void* val) { mcAssert(setsockopt(sfd, level, option, val, sizeof(int)) >= 0, "Socket option set error!"); }

int mcAccept(int sfd, saddr* addr, socklen_t* addrLen)
{
    int clientSFD = -1;
    mcAssert((clientSFD = accept(sfd, addr, addrLen)) != -1, "Error accepting client!");
    return clientSFD;
}

void mcDisconnect(int sfd)
{
    saddr emptyAddr = mcGetEmptyAddr();
    mcConnect(sfd, &emptyAddr, sizeof(saddr));
}

int mcSendTo(int sfd, const void* buffer, int n, int flags, saddr* addr, socklen_t addrLen)
{
    int result = -1;
    while((result = sendto(sfd, buffer, clamp(n,0,MREPRO_MAX_PACKET_SIZE), flags, addr, addrLen)) == -1 && errno == EINTR);
    mcAssert(result != -1, "Error while receiving!");
    return result;
}

ssize_t mcSendNTo(int sfd, const void* buffer, size_t n, saddr* addr, socklen_t addrLen)
{
    size_t nleft;
    ssize_t nwritten;
    const char* ptr;

    ptr = (char*)buffer;
    nleft = n;

    mcDebug("Writing... left %zu", nleft);
    while(nleft > 0)
    {
        nwritten = mcSendTo(sfd, ptr, nleft, 0, addr, addrLen);
        mcAssert(nwritten, "Error while writing!");

        mcDebug("Written %d bytes", nwritten);
        nleft -= nwritten;
        ptr += nwritten;
    }

    mcDebug("Written successfuly to a socket!");
    return n;
}

int mcRecvFrom(int sfd, void* buffer, int n, int flags, saddr* addr, socklen_t* addrLen)
{
    int result = -1;
    while((result = recvfrom(sfd, buffer, clamp(n, 0, MREPRO_MAX_PACKET_SIZE), flags, addr, addrLen)) == -1 && errno == EINTR);
    mcAssert(result != -1, "Error while receiving!");
    return result;
}

ssize_t mcRecvNFrom(int sfd, const void* buffer, size_t n, saddr* addr, socklen_t* addrLen)
{
    size_t nleft;
    ssize_t nread;
    char *ptr;
    ptr = (char*)buffer;
    nleft = n;

    mcDebug("Reading... left %zu", nleft);
    while (nleft > 0) 
    {
        *addrLen = sizeof(saddr);
        nread = mcRecvFrom(sfd, ptr, nleft, MSG_WAITALL, addr, addrLen); 
        if(nread == 0)
        {
            mcDebug("EOF!");
            break;
        }
        mcDebug("Read %d", nread);
        nleft -= nread;
        ptr += nread;
    }
    mcDebug("Read successfuly from a socket!");
    return (n - nleft);
}

//TODO: do something with read(). Wrap it too? too much wrapping
ssize_t mcReadN(int sfd, const void* buffer, size_t n)
{
    size_t nleft;
    ssize_t nread;
    char *ptr;
    ptr = (char*)buffer;
    nleft = n;

    mcDebug("Reading... left %zu", nleft);
    while (nleft > 0) 
    {
        if((nread = read(sfd, ptr, nleft)) < 0) 
        {
            if (errno == EINTR) nread = 0; 
            else mcAssert(0, "Error while reading!");
        } 
        if(nread == 0)
        {
            mcDebug("EOF!");
            break;
        }
        mcDebug("Read %d bytes", nread);
        nleft -= nread;
        ptr += nread;
    }
    mcDebug("Read successfuly from a socket!");
    return (n - nleft);
}

ssize_t mcWriteN(int sfd, const void* buffer, size_t n)
{
    size_t nleft;
    ssize_t nwritten;
    const char* ptr;

    ptr = (char*)buffer;
    nleft = n;

    mcDebug("Writing... left %zu", nleft);
    while(nleft > 0)
    {
        if((nwritten = write(sfd, ptr, nleft)) <= 0)
        {
            if(nwritten < 0 && errno == EINTR) nwritten = 0;
            else mcAssert(0, "Error while writing!");
        }
        mcDebug("Written %d bytes", nwritten);
        nleft -= nwritten;
        ptr += nwritten;
    }

    mcDebug("Written successfuly to a socket!");
    return n;
}

ssize_t mcRecvFromUntilByte(int sfd, const void* buffer, size_t maxSize, byte b, saddr* addr, socklen_t* addrLen)
{
    size_t nleft;
    ssize_t nread;
    char *ptr;
    ptr = (char*)buffer;
    nleft = maxSize;
    while (nleft > 0) 
    {
        nread = mcRecvFrom(sfd, ptr, nleft, 0, addr, addrLen);
        if(nread == 0)
        {
            mcDebug("EOF!");
            break;
        }

        nleft -= nread;
        ptr += nread;

        if(*(ptr-1) == b) break;
    }

    mcDebug("Read successfuly until byte from a socket!");
    return (maxSize - nleft);
}

ssize_t mcReadUntilByte(int sfd, const void* buffer, size_t maxSize, byte b)
{
    size_t nleft;
    ssize_t nread;
    char *ptr;
    ptr = (char*)buffer;
    nleft = maxSize;
    while (nleft > 0) 
    {
        if((nread = read(sfd, ptr, nleft)) < 0) 
        {
            if (errno == EINTR) nread = 0; 
            else return -1;
        } 
        if(nread == 0)
        {
            mcDebug("EOF!");
            break;
        }

        nleft -= nread;
        ptr += nread;

        if(*(ptr-1) == b) break;
    }

    mcDebug("Read successfuly until byte from a socket!");
    return (maxSize - nleft);
}

ssize_t mcReadUntilWord(int sfd, const void* buffer, size_t maxSize, const char* word)
{
    int wordLen = strlen(word);
    size_t nleft;
    ssize_t nread;
    char *ptr;
    ptr = (char*)buffer;
    nleft = maxSize;
    while (nleft > 0) 
    {
        if((nread = read(sfd, ptr, nleft)) < 0) 
        {
            if (errno == EINTR) nread = 0; 
            else return -1;
        } 
        if(nread == 0)
        {
            mcDebug("EOF!");
            break;
        }

        nleft -= nread;
        ptr += nread;

        if(maxSize - nleft >= wordLen)
        {
            if(!strncmp(word, ptr-wordLen, wordLen)) 
            {
                mcDebug("Word reached!");
                break;
            }
        }
    }

    mcDebug("Read successfuly until byte from a socket!");
    return (maxSize - nleft);
}

//TODO check if it works
ssize_t mcSendBinFileTo(int sfd, FILE* fp, saddr* addr, socklen_t addrLen)
{
    mcAssert(connect(sfd, addr, addrLen) == 0, "Socket connect error!");
    ssize_t result = mcWriteBinFile(sfd, fp);
    mcDisconnect(sfd);
    return result;
}

ssize_t mcWriteBinFile(int sfd, FILE* fp)
{
    mcDebug("Sending bin file to socket");

    u32 bytesRead = 0U;
    u32 bytesSent = 0U;

    byte* buffer = (byte*)malloc(MREPRO_MAX_PACKET_SIZE);
    while((bytesRead = fread(buffer, 1, MREPRO_MAX_PACKET_SIZE, fp)) > 0)
    {
        mcAssert(mcWriteN(sfd, buffer, bytesRead) != -1, "Send bin file error!");
        bytesSent += bytesRead;
    }
    free(buffer);
    mcDebug("File sent successfully!");
    return bytesSent;
}

//TODO check if it works
ssize_t mcRecvBinFileFrom(int sfd, FILE* fp, saddr* addr, socklen_t addrLen)
{
    mcAssert(connect(sfd, addr, addrLen) == 0, "Socket connect error!");
    ssize_t result = mcReadBinFile(sfd, fp);
    mcDisconnect(sfd);
    return result;
}

ssize_t mcReadBinFile(int sfd, FILE* fp)
{
    mcDebug("Writing data from socket to file");

    u32 totalBytesReceived = 0;
    u32 bytesReceived = 0;

    byte* buffer = (byte*)malloc(MREPRO_MAX_PACKET_SIZE);

    while((bytesReceived = mcReadN(sfd, buffer, MREPRO_MAX_PACKET_SIZE)) > 0)
    {
        fwrite(buffer, 1, bytesReceived, fp);
        totalBytesReceived += bytesReceived;
    }

    mcAssert(bytesReceived == 0, "Receiving error!");
    mcDebug("Data written successfuly to file, size: %u!", totalBytesReceived);
    free(buffer);

    return totalBytesReceived;
}

ainfo mcAddrInfoHints(mcNetProtocol_ protocol, mcNetFamily_ family, bool passive)
{
    ainfo hints;
    memset(&hints, 0, sizeof(hints));

    // hints.ai_addr
    // hints.ai_addrlen
    // hints.ai_canonname
    hints.ai_family = family;
    hints.ai_flags = passive ? AI_PASSIVE : 0;
    // hints.ai_next
    hints.ai_protocol = protocol;
    if(protocol)
    {
        hints.ai_socktype = protocol == mcNetProtocol_TCP ? SOCK_STREAM : SOCK_DGRAM;
    }

    return hints;
}

socklen_t mcGetSockLocalAddr(int sfd, saddr* localAddr)
{
    memset(localAddr, 0, sizeof(saddr));
    socklen_t addrLen = sizeof(saddr);     

    mcAssert(getsockname(sfd, localAddr, &addrLen) == 0, "Error getting socket name!");
    return addrLen;
}

socklen_t mcGetSockPeerAddr(int sfd, saddr* peerAddr)
{
    memset(peerAddr, 0, sizeof(saddr));
    socklen_t peerLen = sizeof(saddr);

    int result = getpeername(sfd, peerAddr, &peerLen);
    mcAssert(result != -1 || errno == ENOTCONN, "Error getting socket peer name!");

    return result != -1 ? peerLen : 0;
}

mcNetProtocol_ mcGetSockProtocol(int sfd)
{
    int protocol = 0;
    socklen_t protoLen = sizeof(int);

    mcAssert(getsockopt(sfd, SOL_SOCKET, SO_PROTOCOL, &protocol, &protoLen) == 0, "Error getting socket option!");

    return (mcNetProtocol_)protocol;
}

ainfo* mcGetAddrInfo(const char* name, const char* service, ainfo* hints)
{
    ainfo* addr;

    int err = getaddrinfo(name, service, hints, &addr);
    mcAssert
    (
        err == 0, 
        "Getting address info error for %s %s -> %s", name, service, gai_strerror(err)
    );

    return addr;
}

void mcGetNameInfo(saddr* addr, socklen_t addrLen, const char* ip, const char* port, int flags)
{
    mcAssert(getnameinfo(addr, addrLen, (char* restrict)ip, INET6_ADDRSTRLEN, (char* restrict)port, NI_MAXHOST, flags) == 0, "Error getting name info!");
}

const char* mcGetAddrTxt(const saddr* addr)
{
    char* addrTxt = (char*)malloc(INET6_ADDRSTRLEN);
    memset(addrTxt, 0, INET6_ADDRSTRLEN);

    if(addr->sa_family == mcNetFamily_4)
    {
        mcAssert(inet_ntop(mcNetFamily_4, &((saddrin*)addr)->sin_addr, addrTxt, INET6_ADDRSTRLEN) != NULL, "Could not convert addr to text format!");
    }
    else if(addr->sa_family == mcNetFamily_6)
    {
        mcAssert(inet_ntop(mcNetFamily_6, &((saddrin6*)addr)->sin6_addr, addrTxt, INET6_ADDRSTRLEN) != NULL, "Could not convert addr to text format!");
    }
    else mcAssert(0, "Unknown family type!");

    return addrTxt;
}

const char* mcIpNtoP(uint32_t netOrderAddr)
{
    char* addrTxt = (char*)malloc(INET6_ADDRSTRLEN);
    memset(addrTxt, 0, INET6_ADDRSTRLEN);

    mcAssert(inet_ntop(mcNetFamily_4, &netOrderAddr, addrTxt, INET6_ADDRSTRLEN) != NULL, "Could not convert addr to text format!");

    return addrTxt;
}

const char* mcPortNtoP(short netOrderPort)
{
    char *port = (char*)calloc(6, 1);
    sprintf(port, "%hd", ntohs(netOrderPort));
    return port;
}

saddr mcGetEmptyAddr()
{
    saddr emptyAddr;
    memset(&emptyAddr, 0, sizeof(emptyAddr));
    emptyAddr.sa_family = AF_UNSPEC;
    return emptyAddr;
}

int mcSocket(mcNetProtocol_ protocol, mcNetFamily_ family)
{
    ainfo hints = mcAddrInfoHints(protocol, family, false);

    int sfd;
    mcAssert((sfd = socket(hints.ai_family, hints.ai_socktype, hints.ai_protocol)) >= 0, "Socket creation error!");

    // if(protocol == mcNetProtocol_TCP)
    // {
        mcAssert(setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &mcTrue, sizeof(int)) >= 0, "Socket option set error!");
    // }
    mcAssert(setsockopt(sfd, SOL_SOCKET, SO_BROADCAST, &mcTrue, sizeof(int)) >= 0, "Socket option set error!");

    return sfd;
}

int mcServerSFD(const char* port, mcNetProtocol_ protocol, mcNetFamily_ family)
{
    ainfo hints = mcAddrInfoHints(protocol, family, true);
    ainfo* addr = mcGetAddrInfo(NULL, port, &hints);

    int sfd;
    mcAssert((sfd = socket(hints.ai_family, hints.ai_socktype, hints.ai_protocol)) >= 0, "Server socket creation error!");

    // if(protocol == mcNetProtocol_TCP)
    // {
        mcAssert(setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &mcTrue, sizeof(int)) >= 0, "Server socket option set error!");
    // }
    mcAssert(setsockopt(sfd, SOL_SOCKET, SO_BROADCAST, &mcTrue, sizeof(int)) >= 0, "Socket option set error!");

    mcAssert(bind(sfd, addr->ai_addr, addr->ai_addrlen) == 0, "Server socket bind error!");

    if(protocol == mcNetProtocol_TCP)
    {
        mcAssert(listen(sfd, MREPRO_SOCKET_NUM_LISTEN) == 0, "Server socket listen error!");
    }

    freeaddrinfo(addr);
    return sfd;
}

int mcClientSFDFromName(const char* server, const char* service, mcNetProtocol_ protocol, mcNetFamily_ family)
{
    ainfo hints = mcAddrInfoHints(protocol, family, false);
    ainfo* serverAddr = mcGetAddrInfo(server, service, &hints);

    int sfd;
    mcAssert((sfd = socket(hints.ai_family, hints.ai_socktype, hints.ai_protocol)) >= 0, "Socket creation error!");

    // if(protocol == mcNetProtocol_TCP)
    // {
        mcAssert(setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &mcTrue, sizeof(int)) >= 0, "Socket option set error!");
    // }
    mcAssert(setsockopt(sfd, SOL_SOCKET, SO_BROADCAST, &mcTrue, sizeof(int)) >= 0, "Socket option set error!");

    mcAssert(connect(sfd, serverAddr->ai_addr, serverAddr->ai_addrlen) == 0, "Socket connect error!");

    freeaddrinfo(serverAddr);
    return sfd;
}

int mcClientSFDFromAddr(saddr* addr, socklen_t addrLen, mcNetProtocol_ protocol)
{
    char host[INET6_ADDRSTRLEN];
    char service[NI_MAXSERV];
    getnameinfo(addr, addrLen, host, INET6_ADDRSTRLEN, service, NI_MAXSERV, 0);

    mcDebug("Host: %s | Service: %s", host, service);

    return mcClientSFDFromName(host, service, protocol, addr->sa_family);
}

void mcRunSimpleServer(int sfd, mcSimpleServerDispatchFunc dispatchFunc)
{
    saddr sockAddr;
    saddr emptyAddr = mcGetEmptyAddr();
    int protocol = mcGetSockProtocol(sfd);
    mcGetSockLocalAddr(sfd, &sockAddr);

    saddr clientAddr;
    socklen_t clientLen;
    int clientSFD;

    mcRunning = true;
    mcOverrideSignalDispatchFunc(SIGINT, NULL);
    while(mcRunning)
    {
        clientLen = sockAddr.sa_family == mcNetFamily_4 ? sizeof(saddrin) : sizeof(saddrin6);
        
        mcDebug("Awaiting request...");
        
        if(protocol == mcNetProtocol_TCP)
        {
            mcAssert((clientSFD = accept(sfd, &clientAddr, &clientLen)) != -1, "TCP Accept was unsuccessful!");

            dispatchFunc(clientSFD);

            mcAssert(close(clientSFD) != -1, "Socket close error!");
        }
        else if(protocol == mcNetProtocol_UDP)
        {
            byte tmp = 0;
            mcAssert(recvfrom(sfd, &tmp, 1, MSG_WAITALL | MSG_PEEK, &clientAddr, &clientLen) != -1, "UDP Accept was unsuccessful");
            mcAssert(connect(sfd, &clientAddr, clientLen) == 0, "Could not connect to UDP client!");
            clientSFD = sfd;
            
            dispatchFunc(clientSFD);

            mcAssert(connect(clientSFD, &emptyAddr, sizeof(emptyAddr)) == 0, "Unable to dissolve UDP connection!");
        } else mcAssert(0, "Unknown protocol!");

        mcDebug("Closing connection...");
    }

    mcDebug("Shutting down...");
    mcClose(sfd);
}

static void mcFreeListenerEntry(mcListenerEntry entry)
{
    mcClose(entry.pollFD.fd);
    free(entry.data);
}

void mcResetListenerHandle(mcListenerHandle* listenerHandle)
{
    if(listenerHandle->numEntries == 0)
    {
        mcDebug("Server Handle already empty!");
    }
    else
    {
        for(int i = 0; i < listenerHandle->numEntries; i++)
        {
            mcFreeListenerEntry(listenerHandle->entries[i]);
        }
        free(listenerHandle->entries);
        listenerHandle->numEntries = 0;
    }
}

void mcAppendListenerEntry(mcListenerHandle* listenerHandle, mcListenerEntry* entry)
{
    for(int i = 0; i < listenerHandle->numEntries; i++)
    {
        if(listenerHandle->entries[i].pollFD.fd == entry->pollFD.fd)
        {
            mcDebug("File descriptor %d updated!", entry->pollFD.fd);
            listenerHandle->entries[i] = *entry;
            return;
        }
    }

    listenerHandle->numEntries++;
    listenerHandle->entries = realloc(listenerHandle->entries, listenerHandle->numEntries * sizeof(mcListenerEntry));
    listenerHandle->entries[listenerHandle->numEntries - 1] = *entry;

    mcDebug("File descriptor %d appended to listenerHandle", entry->pollFD.fd);
}

void mcAppendListenerFD(mcListenerHandle* listenerHandle, int fd, mcListenerDispatchFunc func, void* data, int eventFlags)
{
    pfd pollFD;
    pollFD.fd = fd;
    pollFD.events = eventFlags;
    pollFD.revents = 0;

    mcListenerEntry entry;
    entry.data = data;
    entry.func = func;
    entry.pollFD = pollFD;

    mcAppendListenerEntry(listenerHandle, &entry);
}

/* Internal -> pops top pollFD from listenerHandle. Doesnt free pointers at popped memory */
static void mcPopListenerPFD(mcListenerHandle* listenerHandle)
{
    listenerHandle->numEntries--;
    listenerHandle->entries = realloc(listenerHandle->entries, listenerHandle->numEntries * sizeof(mcListenerEntry));
}

void mcRemoveListenerFD(mcListenerHandle* listenerHandle, int fd)
{
    int pos = -1;

    for(int i = 0; i < listenerHandle->numEntries; i++)
    {
        if(listenerHandle->entries[i].pollFD.fd == fd)
        {
            pos = i;
            mcFreeListenerEntry(listenerHandle->entries[i]);
            break;
        }
    }

    if(pos == -1)
    {
        mcWarn("File descriptor %d already not in server handle!", fd);
    }
    else
    {
        for(int i = pos; i < listenerHandle->numEntries - 1; i++)
        {
            listenerHandle->entries[i] = listenerHandle->entries[i+1];
        }
        mcPopListenerPFD(listenerHandle);
        mcTrace("File descriptor %d removed from listenerHandle", fd);
    }
}

void mcRemoveListenerEntry(mcListenerHandle* listenerHandle, mcListenerEntry* listenerEntry)
{
    mcRemoveListenerFD(listenerHandle, listenerEntry->pollFD.fd);
}

int mcPollListener(mcListenerHandle* listenerHandle, int timeout)
{
    pfd* fds = (pfd*)malloc(sizeof(pfd) * listenerHandle->numEntries);

    for(int i = 0; i < listenerHandle->numEntries; i++)
    {
        fds[i] = listenerHandle->entries[i].pollFD;
    }

    int ready = poll(fds, listenerHandle->numEntries, timeout);

    for(int i = 0; i < listenerHandle->numEntries; i++)
    {
        listenerHandle->entries[i].pollFD = fds[i];
    }

    free(fds);
    return ready;
}

void mcRunPollServer(mcListenerHandle* listenerHandle, int timeout, mcServerTimeoutFunc timeoutFunc)
{
    mcRunning = true;
    mcOverrideSignalDispatchFunc(SIGINT, NULL); // Upon Ctrl+C, it frees server memory
    while(listenerHandle->numEntries && mcRunning)
    {
        int ready = mcPollListener(listenerHandle, timeout);

        if(ready)
        {
            for(int i = 0; i < listenerHandle->numEntries; i++)
            {
                if(listenerHandle->entries[i].pollFD.events & listenerHandle->entries[i].pollFD.revents)
                {
                    listenerHandle->entries[i].pollFD.revents = 0; // TODO: Put after function call?
                    listenerHandle->entries[i].func(i, listenerHandle);
                    i--; //In case of removal of some descriptor at smaller or equal index (TODO reset to 0 always?)
                }
            }
        }
        else if(timeoutFunc != NULL) timeoutFunc(listenerHandle);
    }

    mcDebug("Shutting down...");
    for(int i = listenerHandle->numEntries - 1; i >= 0; i--)
    {
        mcRemoveListenerEntry(listenerHandle, &listenerHandle->entries[i]);
    }
    mcDebug("Successfuly shut down!");
}

void mcListenerForEach(mcListenerHandle* listenerHandle, mcListenerDispatchFunc dispatchFunc)
{
    for(int i = 0; i < listenerHandle->numEntries; i++)
    {
        dispatchFunc(i, listenerHandle);
    }
}

#endif //MREPRO_COMMON_IMPL_xxx

/*** Filesystem ***/
#if defined(MREPRO_COMMON_IMPL_DEBUG) || defined(MREPRO_COMMON_IMPL_RELEASE)

bool mcFileExists(const char* filename) { return access(filename, F_OK) == 0; }
bool mcIsFileR(const char* filename)    { return access(filename, R_OK) == 0; }
bool mcIsFileW(const char* filename)    { return access(filename, W_OK) == 0; }
bool mcIsFileRW(const char* filename)   { return access(filename, R_OK | W_OK) == 0; }

void mcChdir(const char* dir)           { mcAssert(chdir(dir) != -1, "Error changing directory!"); }

ssize_t mcGetFileBinSize(FILE* fp)
{
    ssize_t length;
    ssize_t pos = ftell(fp);

    fseek(fp, 0, SEEK_END);
    length = ftell(fp);
    fseek(fp, pos, SEEK_SET);

    return length;
}

const char* mcGetFileExtenstion(const char* filename)
{
    const char* dot = strrchr(filename, '.');
    if (dot && dot != filename && *(dot + 1) != '\0') 
    {
        return dot + 1;
    }
    return "";
}

#endif //MREPRO_COMMON_IMPL_xxx

/*** Threads | Signals | Daemons ***/
#if defined(MREPRO_COMMON_IMPL_DEBUG) || defined(MREPRO_COMMON_IMPL_RELEASE)

void mcDaemon(int nochdir, const char* logTitle, int logOption, int logFacility) 
{
    mcAssert(mcDemonProcess == false, "Process is already a demon!");
    mcAssert(daemon(nochdir, 0) == 0, "Error in demonization!"); 

    mcDemonProcess = true;
    mcSyslogOption = logOption;
    mcSyslogFacility = logFacility;

    mcSetLogTitle(logTitle);
}

void mcPthreadCreate(pthread_t* threadID, mcThreadDispatchFunc func, void* args)
{
    if(threadID == NULL)
    {
        pthread_t id;
        int status = pthread_create(&id, NULL, func, args);
        mcAssert(!status, "Error while creating a thread!");
        pthread_detach(id);
    }
    else
    {
        int status = pthread_create(threadID, NULL, func, args);
        mcAssert(!status, "Error while creating a thread!");
    }
}

void mcOverrideSignalDispatchFunc(int signum, mcSignalDispatchFunc func)
{
    saction sa;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    if(signum == SIGINT)
    {
        if(func) SigintDispatchFunc = func;
        sa.sa_handler = mcSigintDispatchFuncWrapper;
    }
    else
    {
        sa.sa_handler = func;
    }

    mcAssert(sigaction(signum, &sa, NULL) == 0, "Error setting sigaction!");
}

#endif //MREPRO_COMMON_IMPL_xxx

/*** Math ***/
#if defined(MREPRO_COMMON_IMPL_DEBUG) || defined(MREPRO_COMMON_IMPL_RELEASE)

inline int  min(int a, int b)                   { return (a < b) ? a : b; }
inline int  max(int a, int b)                   { return (a > b) ? a : b; }
inline int  clamp(int value, int min, int max)  { return (value < min) ? min : (value > max) ? max : value; }

#endif //MREPRO_COMMON_IMPL_xxx

#undef CHECK_LOG_LEVEL
#undef LOG

#endif //MREPRO_COMMON_H