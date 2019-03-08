/*
内核模式socket支持库
*/

#if !defined(KSOCKET_H)
#define KSOCKET_H

#if defined(__cplusplus)
extern "C" {
#endif

typedef unsigned char   u_char;
typedef unsigned short  u_short;
typedef unsigned int    u_int;
typedef unsigned long   u_long;

#define AF_INET             2

#define SOCK_STREAM         1
#define SOCK_DGRAM          2
#define SOCK_RAW            3

#define IPPROTO_ICMP        1
#define IPPROTO_TCP         6
#define IPPROTO_UDP         17

#define INADDR_ANY          0x00000000
#define INADDR_LOOPBACK     0x7f000001
#define INADDR_BROADCAST    0xffffffff
#define INADDR_NONE         0xffffffff

#define MSG_OOB             0x1

#define SOMAXCONN           5

#define SD_RECEIVE          0x00
#define SD_SEND             0x01
#define SD_BOTH             0x02

#ifndef FD_SETSIZE
#define FD_SETSIZE          64
#endif

typedef struct fd_set {
    u_int   fd_count;
    int     fd_array[FD_SETSIZE];
} fd_set;

struct hostent {
    char    *h_name;
    char    **h_aliases;
    short   h_addrtype;
    short   h_length;
    char    **h_addr_list;
};

#define h_addr h_addr_list[0]

struct in_addr {
    union {
        struct { u_char s_b1, s_b2, s_b3, s_b4; }   S_un_b;
        struct { u_short s_w1, s_w2; }              S_un_w;
        u_long                                      S_addr;
    } S_un;
};

#define s_addr S_un.S_addr

struct protoent {
    char    *p_name;
    char    **p_aliases;
    short   p_proto;
};

struct servent {
    char    *s_name;
    char    **s_aliases;
    short   s_port;
    char    *s_proto;
};

struct sockaddr {
    u_short sa_family;
    char    sa_data[14];
};

struct sockaddr_in {
    short           sin_family;
    u_short         sin_port;
    struct in_addr  sin_addr;
    char            sin_zero[8];
};

struct timeval {
    long tv_sec;
    long tv_usec;
};

INT_PTR __cdecl accept(INT_PTR socket, struct sockaddr *addr, int *addrlen);
int __cdecl bind(INT_PTR socket, const struct sockaddr *addr, int addrlen);
int __cdecl close(INT_PTR socket);
int __cdecl connect(INT_PTR socket, const struct sockaddr *addr, int addrlen);
struct hostent * __cdecl gethostbyaddr(const char *addr, int addrlen, int type);
struct hostent * __cdecl gethostbyname(const char *name);
int __cdecl gethostname(char *name, int namelen);
int __cdecl getpeername(INT_PTR socket, struct sockaddr *addr, int *addrlen);
struct protoent * __cdecl getprotobyname(const char *name);
struct protoent * __cdecl getprotobynumber(int number);
struct servent * __cdecl getservbyname(const char *name, const char *proto);
struct servent * __cdecl getservbyport(int port, const char *proto);
int __cdecl getsockname(INT_PTR socket, struct sockaddr *addr, int *addrlen);
int __cdecl getsockopt(INT_PTR socket, int level, int optname, char *optval, int *optlen);
u_long __cdecl htonl(u_long hostlong);
u_short __cdecl htons(u_short hostshort);
u_long __cdecl inet_addr(const char *name);
int __cdecl inet_aton(const char *name, struct in_addr *addr);
char * __cdecl inet_ntoa(struct in_addr addr);
int __cdecl listen(INT_PTR socket, int backlog);
u_long __cdecl ntohl(u_long netlong);
u_short __cdecl ntohs(u_short netshort);
int __cdecl recv(INT_PTR socket, char *buf, int len, int flags);
int __cdecl recvfrom(INT_PTR socket, char *buf, int len, int flags, struct sockaddr *addr, int *addrlen);
int __cdecl select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout);
int __cdecl send(INT_PTR socket, const char *buf, int len, int flags);
int __cdecl send_mdl(INT_PTR socket, PMDL mdl, int flags);
int __cdecl send_mdl_async(INT_PTR socket, PMDL mdl, int flags, void (*completion_routine)(int status, void *context), void *context);
int __cdecl sendto(INT_PTR socket, const char *buf, int len, int flags, const struct sockaddr *addr, int addrlen);
int __cdecl sendto_mdl(INT_PTR socket, PMDL mdl, int flags, const struct sockaddr *addr, int addrlen);
int __cdecl setsockopt(INT_PTR socket, int level, int optname, const char *optval, int optlen);
int __cdecl shutdown(INT_PTR socket, int how);
INT_PTR __cdecl socket(int af, int type, int protocol);

#if defined(__cplusplus)
}
#endif

#endif // !defined(KSOCKET_H)
