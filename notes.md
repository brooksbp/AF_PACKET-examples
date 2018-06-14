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

```protocol``` - ```/usr/include/linux/if_ether.h```

```
htons(ETH_P_IP  0x0800)
non DIX types:
htons(ETH_P_ALL 0x0003) - all protocols received
```

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

```
arch/arm64/include/asm/current.h

  #define current get_current()
    return (struct task_struct *)mrs SP_EL0

arch/arm64/include/asm/uaccess.h

  #define access_ok(type, addr, size)  __range_ok(addr, size)
    __range_ok(addr, size)  // test whether block of memory is valid user space address
      ..
```

```
include/uapi/linux/uio.h

  struct iovec               <- matches POSIX-defined structure!
  {
    void __user *iov_base;
    __kernel_size_t iov_len;
  };

  struct iov_iter {
    int type;
    size_t iov_offset;
    size_t count;
    union {
      const struct iovec *iov;
      const struct kvec *kvec;
      const struct bio_vec *bvec;
      struct pipe_inode_info *pipe;
    };
    union {
      unsigned long nr_segs;
      struct {
        int idx;
        int start_idx;
      };
    };
```

```
1362:SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)

static struct vfsmount *sock_mnt;

static const struct net_proto_family __rcu *net_families[NPROTO];

__sys_socket()
  sock_create()
    struct socket *sock;
    __sock_create(.., &sock)
      sock = sock_alloc()
        inode = new_inode_pseudo(sock_mnt->mnt_sb)
          inode = alloc_inode(struct super_block sb)
        sock = SOCKET_I(inode) //socketFromInode
        inode->i_op = &sockfs_inode_ops
        return sock
+     pf = rcu_dereference(net_families[family])
+     pf->create(net, sock, protocol, kern)
    return sock_map_fd(sock)
      fd = get_unused_fd_flags(flags)
        __alloc_fd(current->files, 0, rlimit(RLIMIT_NOFILE), flags)
      newfile = sock_alloc_file()
      fd_install(fd, newfile)
```

```
1493:SYSCALL_DEFINE3(bind, int, fd, struct sockaddr __user *, umyaddr, int, addrlen)

__sys_bind()
  sock = sockfd_lookup_light(fd)
    struct fd f = fdget(fd))
    return sock_from_file(f.file)
  move_addr_to_kernel() //copy_from_user(kaddr, uaddr, ulen)
+ sock->ops->bind()
```

```
1525:SYSCALL_DEFINE2(listen, int, fd, int, backlog)

__sys_listen()
  sock = sockfd_lookup_light(fd)
    if (backlog > somaxconn)
      backlog = somaxconn
+   sock->ops->listen()
```

```
1797:SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, size_t, len,
1808:SYSCALL_DEFINE4(send, int, fd, void __user *, buff, size_t, len,

__sys_sendto(int fd,
             void __user *buff,
             size_t len,
             unsigned int flags,
             struct sockaddr __user *addr,
             int addr_len)
  struct msghdr msg;
  struct iovec iov;
  import_single_range(WRITE, buff, len, &iov, i = (struct iov_iter *)&msg.msg_iter)
    iov->iov_base = buf
    iov->iov_len = len
    iov_iter_init(i, rw, iov, 1, len)
      i->xxx =
      i->xxx =
  sock = sockfd_lookup_light(fd))
  msg.xxx =
  msg.xxx =
  sock_sendmsg(sock, &msg)
+   sock->ops->sendmsg(sock, msg, msg_data_left(msg))
```

```
1860:SYSCALL_DEFINE6(recvfrom, int, fd, void __user *, ubuf, size_t, size,
1871:SYSCALL_DEFINE4(recv, int, fd, void __user *, ubuf, size_t, size,

__sys_recvfrom(int fd,
               void __user *ubuf,
               size_t size,
               unsigned int flags,
               struct sockaddr __user *addr,
               int __user *addr_len)
  struct iovec iov;
  struct msghdr msg;
  import_single_range(READ, ubuf, size, &iov, &msg.msg_iter)
  ..
  sock_recvmsg(sock, &msg, flags)
    sock->ops->recvmsg(sock, msg, msg_data_left(msg), flags)
```

## AF_PACKET Implementation

```
SOCK_DGRAM
SOCK_RAW
SOCK_PACKET  <--- OBSOLETE and should not be used!
```

```
include/linux/netdevice.h

struct packet_type {
        __be16                  type;   /* This is really htons(ether_type). */
        struct net_device       *dev;   /* NULL is wildcarded here           */
    	int                     (*func) (struct sk_buff *,
                                         struct net_device *,
                                         struct packet_type *,
                                         struct net_device *);
        bool                    (*id_match)(struct packet_type *ptype,
                                            struct sock *sk);
        void                    *af_packet_priv;
        struct list_head        list;
};
```

```
net/packet/internal.h

/* kbdq - kernel block descriptor queue */
struct tpacket_kbdq_core {
        struct pgv      *pkbdq;
        unsigned int    feature_req_word;
        unsigned int    hdrlen;
        unsigned char   reset_pending_on_curr_blk;
        unsigned char   delete_blk_timer;
        unsigned short  kactive_blk_num;
        unsigned short  blk_sizeof_priv;

        /* last_kactive_blk_num:
         * trick to see if user-space has caught up
         * in order to avoid refreshing timer when every single pkt arrives.
         */
        unsigned short  last_kactive_blk_num;

        char            *pkblk_start;
        char            *pkblk_end;
        int             kblk_size;
        unsigned int    max_frame_len;
        unsigned int    knum_blocks;
        uint64_t        knxt_seq_num;
        char            *prev;
        char            *nxt_offset;
        struct sk_buff  *skb;

        atomic_t        blk_fill_in_prog;

        /* Default is set to 8ms */
#define DEFAULT_PRB_RETIRE_TOV  (8)

        unsigned short  retire_blk_tov;
        unsigned short  version;
        unsigned long   tov_in_jiffies;

        /* timer to retire an outstanding block */
        struct timer_list retire_blk_timer;
};

struct pgv {
	char *buffer;
};

struct packet_ring_buffer {
	struct pgv              *pg_vec;

	unsigned int            head;
	unsigned int            frames_per_block;
	unsigned int            frame_size;
	unsigned int            frame_max;

	unsigned int            pg_vec_order;
	unsigned int            pg_vec_pages;
	unsigned int            pg_vec_len;

	unsigned int __percpu   *pending_refcnt;

	struct tpacket_kbdq_core        prb_bdqc;
};

struct packet_sock {
        /* struct sock has to be the first member of packet_sock */
        struct sock             sk;
        struct packet_fanout    *fanout;
        union  tpacket_stats_u  stats;
        struct packet_ring_buffer       rx_ring;
        struct packet_ring_buffer       tx_ring;
        int                     copy_thresh;
        spinlock_t              bind_lock;
        struct mutex            pg_vec_lock;
        unsigned int            running;        /* bind_lock must be held */
        unsigned int            auxdata:1,      /* writer must hold sock lock */
                                origdev:1,
                                has_vnet_hdr:1,
                                tp_loss:1,
                                tp_tx_has_off:1;
        int                     pressure;
        int                     ifindex;        /* bound device         */
        __be16                  num;
        struct packet_rollover  *rollover;
        struct packet_mclist    *mclist;
        atomic_t                mapped;
        enum tpacket_versions   tp_version;
        unsigned int            tp_hdrlen;
        unsigned int            tp_reserve;
        unsigned int            tp_tstamp;
        struct net_device __rcu *cached_dev;
        int                     (*xmit)(struct sk_buff *skb);
        struct packet_type      prot_hook ____cacheline_aligned_in_smp;
};

static struct packet_sock *pkt_sk(struct sock *sk)
{
        return (struct packet_sock *)sk;
}
```

```
net/packet/af_packet.c

__init packet_init()
  proto_register(&packet_proto)                          PACKET, sizeof(struct packet_sock)
  sock_register(&packet_family_ops)                      PF_PACKET, packet_create()
  register_pernet_subsys(&packet_net_ops)                packet_net_init()
                                                         packet_net_exit()
  register_netdevice_notifier(&packet_netdev_notifier)   packet_notifier()

packet_create(struct net *net,
              struct socket *sock,
              int protocol,
              int kern)
  struct sock *sk = sk_alloc(net, PF_PACKET, GFP_KERNEL, &packet_proto, kern)
    sk_prot_alloc()
      sk = kmalloc(prot->obj_size, priority)
      sk_tx_queue_clear(sk)
      return sk
+ sock->ops = &packet_ops
+ sock_init_data(sock, sk)
    ..
    sk_init_common()
      skb_queue_head_init(&sk->sk_receive_queue)
      skb_queue_head_init(&sk->sk_write_queue)
      skb_queue_head_init(&sk->sk_error_queue)
    ..
+ po->xmit = dev_queue_xmit
+ packet_alloc_pending(po)
    po->rx_ring.pending_refcnt = NULL
    po->tx_ring.pending_refcnt = alloc_percpu(unsigned int)
  RCU_INIT_POINTER(po->cached_dev, NULL)
+ po->prot_hook.func = packet_rcv;
  po->prot_hook.af_packet_priv = sk;
  if (protocol)
    __register_prot_hook(sk)
      if (po->fanout)
        __fanout_link(sk, po)
      else
        dev_add_pack(&po->prot_hook)
          list_add_rcu(&pt->list, head)
      sock_hold(sk)
        refcount_inc(&sk->sk_refcnt)
  preempt_disable()
  sock_prot_inuse_add(net, &packet_proto, 1)
    __this_cpu_add(net->core.prot_inuse->val[prot->inuse_idx], val)
  preempt_enable()
```

```
static const struct proto_ops packet_ops = {
	.family =       PF_PACKET,
	.owner =        THIS_MODULE,
	.release =      packet_release,
	.bind =         packet_bind,
	.connect =      sock_no_connect,      return -EOPNOTSUPP
	.socketpair =   sock_no_socketpair,   return -EOPNOTSUPP
	.accept =       sock_no_accept,       return -EOPNOTSUPP
	.getname =      packet_getname,
	.poll =         packet_poll,
	.ioctl =        packet_ioctl,
	.listen =       sock_no_listen,       return -EOPNOTSUPP
	.shutdown =     sock_no_shutdown,     return -EOPNOTSUPP
	.setsockopt =   packet_setsockopt,
	.getsockopt =   packet_getsockopt,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_packet_setsockopt,
#endif
    .sendmsg =      packet_sendmsg,
	.recvmsg =      packet_recvmsg,
	.mmap =         packet_mmap,
	.sendpage =     sock_no_sendpage,     return -EOPNOTSUPP
};
```

```
packet_bind()
  packet_do_bind(sk,        // Attach a packet hook
                 NULL,
                 sll->sll_ifindex,
                 sll->sll_protocol ? : pkt_sk(sk)->num)
    if (po->fanout)
      return -EINVAL
    struct net_device *dev = dev_get_by_index_rcu(sock_net(sk), ifindex)
    dev_hold(dev)  // Hold reference to device to keep it from being freed
      this_cpu_inc(*dev->pcpu_refcnt)
    if (po->prot_hook.type != proto ||
        po->prot_hook.dev  != dev)
      //rehook
    dev_put(cur_dev) // release reference to device
    register_prot_hook(sk)
```

```
packet_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
  if (po->tx_ring.pg_vec)
    return tpacket_snd(po, msg)
  else
    return packet_snd(sock, msg, len)

packet_snd(sock, msg, len)
  hlen = LL_RESERVED_SPACE(dev)
  tlen = dev->needed_tailroom
+ struct sk_buff *skb = packet_alloc_skb(sk      = sk,
                                         prepad  = hlen + tlen,
                                         reserve = hlen,
                                         len     = len,
                                         linear  = linear,
                                         noblock = msg->msg_flags & MSG_DONTWAIT,
                                         &err)
    skb = sock_alloc_send_pskb(sk             = sk,
                               header_len     = prepad + linear,
                               data_len       = len - linear,
                               noblock        = noblock,
                               err,
                               max_page_order = 0)
      //wait until "transmit queue bytes committed" is less than we need to send it..
      return alloc_skb_with_frags(header_len,
                                  data_len,
                                  max_page_order,
                                  errcode,
                                  sk->sk_allocation)
        npages = (data_len + (PAGE_SIZE - 1)) >> PAGE_SHIFT
        skb = alloc_skb(header_len, ..)
+         __alloc_skb(size, priority, 0, NUMA_NO_NODE)
        for i=0..npages
          alloc_page(..)
          skb_fill_page_desc(..)
    skb_reserve(skb, reserve)
    skb_put(skb, linear)
    skb->data_len = len - linear
    skb->len += len - linear
  skb_reset_network_header(skb)
  skb_reserve(dev->hard_header_len)
+ skb_copy_datagram_from_iter(skb, offset, &msg->msg_iter, len)
  dev_validate_header(dev, skb->data, len)
  skb->protocol = proto
  skb->dev      = dev
  skb->priority = sk->sk_priotity
  skb_probe_transport_header(skb, reserve)
+ po->xmit(skb)
  dev_put(dev)
  return len
```

```
// Pull a packet from our receive queue and hand it to user
packet_recvmsg()
  skb = skb_recv_datagram(sk, ..)
  skb_copy_datagram_msg(skb, 0, msg, copied)
  sock_recv_ts_and_drops(msg, sk, skb)
  skb_free_datagram(sk, skb)
```

```
mmap_pgoff()
  ksys_mmap_pgoff()
    vm_mmap_pgoff()
      do_mmap_pgoff()
        do_mmap()
          // verify (or get new) addr and ensure it represents valid section of addr space
          addr = get_unmapped_area(file, addr, len, pgoff, flags)
          addr = mmap_region(file, addr, len, vm_flags, pgoff, uf)
            //clear any old mappings
            struct vm_area_struct *vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL)
            vma->vm_mm        = mm
            vma->vm_start     = addr
            vma->vm_end       = addr + len
            vma->vm_flags     = vm_flags
            vma->vm_page_prot = vm_get_page_prot(vm_flags)
            vma->vm_pgoff     = pgoff
            if (file)
              vma->vm_file = get_file(file)
              call_mmap(file, vma)
+               file->f_op->mmap(file, vma)
            vma_link(mm, vma, ..)
              __vma_link(..)

packet_mmap
  
```

```
prot_hook CALLBACK

packet_rcv
```
