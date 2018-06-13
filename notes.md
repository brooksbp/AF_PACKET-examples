# Notes

## Socket

Sockets are a method of IPC that allow data to be exchanged between applications either on the same host or on different hosts connected by a network.

Socket domains:

```
Domain    Communication   Communication between  Address format          Address structure
          performed       applications

AF_UNIX   within kernel   on same host           pathname                sockaddr_un
AF_INET   via IPv4        hosts on IPv4 network  IPv4 address + L4 port  sockaddr_in
AF_INET6  via IPv6        hosts on IPv6 network  IPv4 address + L4 port  sockaddr_in6
```

Socket types:

```
                                 Stream   Datagram
Reliable delivery?                 Y         N
Message boundaries preserved?      N         Y
Connection-oriented?               Y         N
```

SOCK_STREAM:

Reliable, bidirectional, byte-stream (no message boundaries) communications channel.

```
          Passive socket
            (server)

            socket()
            bind()
            listen()
            accept()               Active socket
                                     (client)

                                     socket()
            *newfd*      <-----      connect()
            read()       <-----      write()
            write()       ---->      read()

            close()                  close()
```

SOCK_DGRAM:

Connectionless - doesn't need to be connected to another socket in order to be used.

```
           Server                  Client

           socket()
           bind()                  socket()

           recvfrom()  <---        sendto()
           sendto()         --->   recvfrom()

           close()                 close()
```

SOCK_SEQPACKET:

Connection-oriented, message boundaries preserved, reliable delivery.
SCTP. Supports multiple logical streams over single connection.
DCCP. Supports congestion control, but not reliable or in-order delivery.

sendmsg()/recvmsg():

can do everything write()/send()/sendto() and read()/recv()/recvfrom() can do in addition to:

* Scatter-gather I/O
 * sendmsg() send a single datagram from multiple buffers
 * recvmsg() receive a single datagram into multiple buffers
* Transmit domain-specific ancillary data (control information)
 * AF_UNIX: pass file descriptors around
 * AF_UNIX: receive credentials (user ID, group ID, process ID) of sender

## I/O Models

Traditional blocking - a process performs I/O on just one file descriptor at a time, blocking until it is done.

Additional application needs:

* Is fd ready for I/O without it blocking?
* Are any fds ready for I/O?

Nonblocking I/O - system call returns immediately if I/O would block.

Allows for polling fds one-by-one.

If we don't want to block a process, we can do process-per-fd. Complex and expensive.

SO!

* I/O multiplexing
  * Monitor fds and perform I/O multiplexing with select()/poll()
* Signal-driven I/O
  * Kernel signals process when I/O ready.
* epoll()

Transition of fd into READY state is triggerd by an I/O event.


## Socket API

```
$ ag SYSCALL net/socket.c
1362:SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
1456:SYSCALL_DEFINE4(socketpair, int, family, int, type, int, protocol,
1493:SYSCALL_DEFINE3(bind, int, fd, struct sockaddr __user *, umyaddr, int, addrlen)
1525:SYSCALL_DEFINE2(listen, int, fd, int, backlog)
1623:SYSCALL_DEFINE4(accept4, int, fd, struct sockaddr __user *, upeer_sockaddr,
1629:SYSCALL_DEFINE3(accept, int, fd, struct sockaddr __user *, upeer_sockaddr,
1673:SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr,
1711:SYSCALL_DEFINE3(getsockname, int, fd, struct sockaddr __user *, usockaddr,
1747:SYSCALL_DEFINE3(getpeername, int, fd, struct sockaddr __user *, usockaddr,
1797:SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, size_t, len,
1808:SYSCALL_DEFINE4(send, int, fd, void __user *, buff, size_t, len,
1860:SYSCALL_DEFINE6(recvfrom, int, fd, void __user *, ubuf, size_t, size,
1871:SYSCALL_DEFINE4(recv, int, fd, void __user *, ubuf, size_t, size,
1911:SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname,
1948:SYSCALL_DEFINE5(getsockopt, int, fd, int, level, int, optname,
1973:SYSCALL_DEFINE2(shutdown, int, fd, int, how)
2162:SYSCALL_DEFINE3(sendmsg, int, fd, struct user_msghdr __user *, msg, unsigned int, flags)
2238:SYSCALL_DEFINE4(sendmmsg, int, fd, struct mmsghdr __user *, mmsg,
2335:SYSCALL_DEFINE3(recvmsg, int, fd, struct user_msghdr __user *, msg,
2481:SYSCALL_DEFINE5(recvmmsg, int, fd, struct mmsghdr __user *, mmsg,
2508:SYSCALL_DEFINE2(socketcall, int, call, unsigned long __user *, args)
```

```
struct sockaddr {
    sa_family_t sa_family;
    char        sa_data[14];
};

struct msghdr {
    void         *msg_name;       /* optional address */
    socklen_t     msg_namelen;    /* size of address */
    struct iovec *msg_iov;        /* scatter/gather array */
    size_t        msg_iovlen;     /* # elements in msg_iov */
    void         *msg_control;    /* ancillary data, see below */
    size_t        msg_controllen; /* ancillary data buffer len */
    int           msg_flags;      /* flags (unused) */
};
```

```
int socket(int domain, int type, int protocol);
```
Create an endpoint for communication and return a file descriptor that refers to that endpoint.

```
int socketpair(int domain, int type, int protocol, int sv[2]);
```
Create an unamed pair of connected sockets.

```
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```
Assign an address to a socket.

```
int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
```
Get and set options on a socket.

----------

```
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
```
Send a message on a socket.

```
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
```
Receive messages from a socket.

----------

```
int listen(int sockfd, int backlog);
```
Mark the socket as a passive socket - a socket that will be used to accept incoming connection requests using accept();
Backlog limits the number of pending connection requests.

```
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
```
For connection-based sockets (SOCK_STREAM, SOCK_SEQPACKET).
Extract the first connection request on the queue of pending connections for the listening socket.
Creates a new connected socket for the connection. The socket is not in listening state.

```
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```
Connect the socket to an address.

---------

```
int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```
Get the current address to which the socket is bound.

```
int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```
Get the address of the peer connected to the socket.

```
int shutdown(int sockfd, int how);
```
Shutdown all or part of a full-duplex connection.

```
int socketcall(int call, unsigned long *args);
```
Invoke a socket system call.



XXXX dispatch into af_packet.c ?


## AF_PACKET

```
packet_socket = socket(AF_PACKET, int socket_type, int protocol);
```

SOCK_RAW
* RX - Address is still parsed and placed into a sockaddr_ll
* TX - Packet is queued to network driver of the interface defined by the destination address

SOCK_DGRAM
* RX - link-level header removed
* TX - link-level header added based on sockaddr_ll destination address

htons(ETH_P_ALL) - all protocols received


Use bind() to RX from address on specific interface. Otherwise, RX from all interfaces

```
struct sockaddr_ll {
    unsigned short sll_family;   /* Always AF_PACKET */
    unsigned short sll_protocol; /* Physical-layer protocol */
    int            sll_ifindex;  /* Interface number */
    unsigned short sll_hatype;   /* ARP hardware type */
    unsigned char  sll_pkttype;  /* Packet type */
    unsigned char  sll_halen;    /* Length of address */
    unsigned char  sll_addr[8];  /* Physical-layer address */
};
```

connect() not supported.

---

Socket options:

* PACKET_ADD_MEMBERSHIP
* PACKET_DROP_MEMBERSHIP
  * PACKET_MR_PROMISC - receive all packets
  * PACKET_MR_MULTICAST - bind socket to physical-layer multicast group
* PACKET_AUXDATA
  * Receive aux data in recvmsg()
* PACKET_FANOUT
  * Group of packet sockets
  * 65536 groups per netns
    * The 1st to join creates it
    * Others must be of same type (proto, ..)
  * Algorithms to spread traffic between sockets
    * PACKET_FANOUT_HASH - packet flow hash
    * PACKET_FANOUT_LB - round-robin
    * PACKET_FANOUT_CPU - select socket based on CPU packet arrived on
    * PACKET_FANOUT_ROLLOVER - move to next socket when current gets backlogged
    * PACKET_FANOUT_RND - random
    * PACKET_FANOUT_QM - select socket based on recorded queue_mapping of received skb
  * PACKET_RX_RING
    * Memory-mapped ring buffer for asynchronous packet reception
    * head and tail communicated through tp_status field
    * packet socket owns all slots with tp_status == TP_STATUS_KERNEL
    * After filling slot it transfers ownership to application (TP_STATUS_USER)
    * Multiple variants of the packet ring
  * PACKET_RESERVE
    * rx headroom
  * PACKET_TIMESTAMP
    * Default, when packet is copied into the ring
    * Hardware, timestamping.txt
  * PACKET_TX_RING
  * PACKET_VERSION
    * Default, TPACKET_V1
  * PACKET_STATISTICS
  * PACKET_QDISC_BYPASS
    * Default, packets pass through kernel's qdisc (traffic control) layer

## Socket Implementation

```
$ ag SYSCALL net/socket.c
1362:SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
1456:SYSCALL_DEFINE4(socketpair, int, family, int, type, int, protocol,
1493:SYSCALL_DEFINE3(bind, int, fd, struct sockaddr __user *, umyaddr, int, addrlen)
1525:SYSCALL_DEFINE2(listen, int, fd, int, backlog)
1623:SYSCALL_DEFINE4(accept4, int, fd, struct sockaddr __user *, upeer_sockaddr,
1629:SYSCALL_DEFINE3(accept, int, fd, struct sockaddr __user *, upeer_sockaddr,
1673:SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr,
1711:SYSCALL_DEFINE3(getsockname, int, fd, struct sockaddr __user *, usockaddr,
1747:SYSCALL_DEFINE3(getpeername, int, fd, struct sockaddr __user *, usockaddr,
1797:SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, size_t, len,
1808:SYSCALL_DEFINE4(send, int, fd, void __user *, buff, size_t, len,
1860:SYSCALL_DEFINE6(recvfrom, int, fd, void __user *, ubuf, size_t, size,
1871:SYSCALL_DEFINE4(recv, int, fd, void __user *, ubuf, size_t, size,
1911:SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname,
1948:SYSCALL_DEFINE5(getsockopt, int, fd, int, level, int, optname,
1973:SYSCALL_DEFINE2(shutdown, int, fd, int, how)
2162:SYSCALL_DEFINE3(sendmsg, int, fd, struct user_msghdr __user *, msg, unsigned int, flags)
2238:SYSCALL_DEFINE4(sendmmsg, int, fd, struct mmsghdr __user *, mmsg,
2335:SYSCALL_DEFINE3(recvmsg, int, fd, struct user_msghdr __user *, msg,
2481:SYSCALL_DEFINE5(recvmmsg, int, fd, struct mmsghdr __user *, mmsg,
2508:SYSCALL_DEFINE2(socketcall, int, call, unsigned long __user *, args)
```
