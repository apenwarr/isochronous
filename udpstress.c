/*
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Authors: Tim Shepard, Dave Taht
 * Derived from udpburst: https://gfiber.googlesource.com/vendor/google/platform/+/master/cmds/udpburst.c
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "dscp.h"
#include "test_dscp.h"

#ifndef AI_NUMERICSERV
/* some older linuxen lack this, so do without */
#define AI_NUMERICSERV 0
#warning AI_NUMERICSERV not defined, doing without
#endif

void pe(char *s)
{
  perror(s);
  exit(1);
}

#define PORT 19290

#define MAGIC 0x31f71dc2

#define CMD_SEND 1
#define CMD_SINK 2
#define CMD_TEST 3
#define CMD_TACK 4

struct msg {
  u_int32_t magic;
  u_int32_t cmd;
  u_int32_t cookie;
  u_int32_t n;
  u_int32_t size;
};

/* CMD_TEST */

/* CMD_TACK */

struct logger {
  struct msg msg;
  struct timeval ts;
  uint32_t arrival;
  uint8_t tos;
};

/* summary of results */

struct results {
  uint32_t consecutive;
  uint32_t out_of_order;
  uint32_t adjacent_dups;
  uint32_t count;
  uint32_t recent;
};

void htonmsg(struct msg *m)
{
#define sw(x) x = htonl(x)
  sw(m->magic);
  sw(m->cmd);
  sw(m->cookie);
  sw(m->n);
  sw(m->size);
#undef sw
}

void ntohmsg(struct msg *m)
{
#define sw(x) x = ntohl(x)
  sw(m->magic);
  sw(m->cmd);
  sw(m->cookie);
  sw(m->n);
  sw(m->size);
#undef sw
}

char rbuf[64 * 1024];
char tbuf[64 * 1024];

static uint32_t ecn = 0;
static uint32_t ecn_seen = 0;
static uint32_t ect_seen = 0;
static uint32_t arrivals = 0;
static uint32_t dscp = 0;
static uint32_t dots = 0;
static uint32_t quiet = 0;
static uint32_t sweep = 0;
static uint32_t want_timestamps = 0;
static uint32_t want_tos = 0;
static uint32_t want_server = 0;
static double packets_per_sec = 0.0;
static const int timeout = 16;
static char testname[32];
static uint8_t *dscp_test;

static uint8_t * dscp_data(int option)
{
  switch(option) {
  case 1: return((uint8_t *) &test_cs); break;
  case 2: return((uint8_t *) &test_wifi); break;
  case 3: return((uint8_t *) &test_af); break;
  case 4: return((uint8_t *) &test_tos); break;
  case 5: return((uint8_t *) &test_all); break;
  }
  return 0;
}

static int parse_sweep(char *option)
{
  if(strcmp(option,"cs") == 0) return 1;
  if(strcmp(option,"wifi") == 0) return 2;
  if(strcmp(option,"af") == 0) return 3;
  if(strcmp(option,"tos") == 0) return 4;
  if(strcmp(option,"all") == 0) return 5;
  return 0;
}

uint32_t next_dscp(int ecn, const uint8_t *dscp_range)
{
  static int cur = 1;
  uint32_t dscp = (int) dscp_range[cur] | ecn;
  if (++cur > dscp_range[0]) cur = 1;
  return dscp;
}


/* This generally does not manage to set the tos field reliably 
   and I'm retaining it for a future test to see what happens */

void sweep_dscp_setsockopt(int s, int ecn, uint8_t *dscp_range)
{
  static int cur = 0;
  int dscp = dscp_range[cur] | ecn;
  if ( setsockopt( s, IPPROTO_IPV6, IPV6_TCLASS, &dscp, sizeof (dscp)) < 0 ) {
    //   perror( "setsockopt( IPV6_TCLASS )" );
  }
  if ( setsockopt( s, IPPROTO_IP, IP_TOS, &dscp, sizeof (dscp)) < 0 ) {
    perror( "setsockopt( IP_TOS )" );
  }
  if (dscp_range[++cur] == -1) cur = 0;
}

struct socket_fd {
  int fd;
  int type;
};

int test_burst(void) {
}

int server(void)
{
  int s, r;
  const int ipv6only = 1;
  struct pollfd p[2];
  struct sockaddr_in6 sa, rsa;
  struct sockaddr_in  sa4, rsa4;

  p[1].events = p[0].events = POLLIN;
  p[0].fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  p[1].fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if (p[0].fd < 1) pe("socket");
  if (p[1].fd < 1) pe("socket");

  sa.sin6_family = AF_INET6;
  sa.sin6_port = htons(PORT);
  sa.sin6_flowinfo = 0;
  sa.sin6_addr = in6addr_any;
  sa.sin6_scope_id = 0;

  r = setsockopt(p[0].fd, IPPROTO_IPV6,
			 IPV6_V6ONLY, (char*)&ipv6only, sizeof(ipv6only) );

  r = bind(p[0].fd, (struct sockaddr *) &sa, sizeof sa);
  if (r < 0) pe("bind ipv6");

  sa4.sin_family = AF_INET;
  sa4.sin_port = htons(PORT);
  sa4.sin_addr.s_addr =  htonl(INADDR_ANY);

  r = bind(p[1].fd, (struct sockaddr *) &sa4, sizeof sa4);
  if (r < 0) pe("bind ipv4");

  if ( setsockopt( p[0].fd, IPPROTO_IPV6, IPV6_TCLASS, &dscp, sizeof (dscp)) < 0 ) {
    perror( "setsockopt( IPV6_TCLASS )" );
  }

  if ( setsockopt( p[1].fd, IPPROTO_IP, IP_TOS, &dscp, sizeof (dscp)) < 0 ) {
    perror( "setsockopt( IP_TOS )" );
  }

  dscp |= ecn;
  int tosbits=0;
  
  while(1) {
    poll(p,2,-1);

  if(p[0].revents == POLLIN)
    s = p[0].fd;
  if(p[1].revents == POLLIN)
    s = p[1].fd;

  {
    struct msg *rm = (struct msg *) rbuf;
    struct msg *tm = (struct msg *) tbuf;
    u_int32_t i;
    socklen_t rsa_len = sizeof rsa;
    socklen_t rsa4_len = sizeof rsa4;

    if(s == p[0].fd) 
      r = recvfrom(s, rbuf, sizeof rbuf, 0, (struct sockaddr *) &rsa, &rsa_len);
    else
      r = recvfrom(s, rbuf, sizeof rbuf, 0, (struct sockaddr *) &rsa4, &rsa4_len);

    if (r < 0) pe("recvfrom");

    if (r < (int) sizeof *rm) {
      fprintf(stderr, "ignoring UDP packet too short to contain msg struct\n");
      continue;
    }

    ntohmsg(rm);

    if (rm->cmd != CMD_SEND) {
      fprintf(stderr, "ignoring UDP packet with command other than SEND\n");
      continue;
    }

    if (rm->size < sizeof *rm) {
      fprintf(stderr, "adjusting size of reply messages up to minimum\n");
      rm->size = sizeof *rm;
    }

    if (rm->size > sizeof tbuf) {
      fprintf(stderr, "limiting size of reply messages down to maximum\n");
      rm->size = sizeof tbuf;
    }

    memset(tbuf, 0x5a, sizeof tbuf);
    tm->magic = MAGIC;
    tm->cmd = rm->cmd;
    tm->cookie = rm->cookie;
    tm->n = 0;
    tm->size = rm->size;

    htonmsg(tm);
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
    int *fd_ptr;
    struct msghdr m;
    struct cmsghdr *cmsg;
    struct iovec    iov[2];
    m.msg_controllen = 2 * CMSG_SPACE(sizeof(int));
    char control[m.msg_controllen];
    iov[0].iov_base = tm;
    iov[0].iov_len = MAX(64,rm->size);
    m.msg_iov = &iov[0];
    m.msg_iovlen = 1;
    m.msg_control = control;
    cmsg = CMSG_FIRSTHDR(&m);

    if(s == p[0].fd) {
      cmsg->cmsg_level = IPPROTO_IPV6;
      cmsg->cmsg_type = IPV6_TCLASS;
      m.msg_name = (struct sockaddr *) &rsa;
      m.msg_namelen = sizeof(struct sockaddr_in6); // rsa_len;
    } else {
      cmsg->cmsg_level = IPPROTO_IP;
      cmsg->cmsg_type = IP_TOS;
      m.msg_name = (struct sockaddr *) &rsa4;
      m.msg_namelen = rsa4_len;
    }
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    fd_ptr = (int *) CMSG_DATA(cmsg);
    
    m.msg_controllen = cmsg->cmsg_len;
    for  (i = 0; i < rm->n; i++) {
      tm->n = htonl(i);
      *fd_ptr = sweep > 0 ? next_dscp(ecn,dscp_test) : dscp | ecn;
      r = sendmsg(s, &m, 0);
      if (r < 0) pe("sendto");
      if (r < (int) rm->size)
        fprintf(stderr, "short sendto (expected %d, got %d)\n", rm->size, r);
    }
  }
  } while (1);
  return 0;
}

int sizetoi(char *p)
{
  int r = 0;
  int c;

  while ((c = *p++)) {
    switch (c) {
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
      r *= 10;
      r += c - '0';
      break;
    case 'k': case 'K':
      r *= 1<<10;
      break;
    case 'm': case 'M':
      r *= 1<<20;
      break;
    default:
      return r;
    }
  }
  return r;
}

void tests_show() {
  fprintf(stderr, 
	  "\nDefined diffserv tests:\n"
	  "\t-W cs sweep cs values\n"
	  "\t-W af sweep af values\n"
	  "\t-W wifi sweep common wifi values\n"
	  "\t-W tos  sweep tos values\n"
	  "\t-W all sweep all defined diffserv values\n"
	  );
}

static void usage_and_die(char *argv0, int n, int size) {
      fprintf(stderr, "usage: %s -f{rom} host\n"
      		      "    or    -t{o} host\n"
	              "    or    -S server mode\n"
      		      "          [ -c count ] (default = %d)\n"
	              "          [ -s size  ] (default = %d\n"
	              "          [ -q ] quiet \n"
	              "          [ -d ] print dots \n"
	              "          [ -E ] enable ecn\n"
	              "          [ -D value ] dscp (tos) value \n"
	              "          [ -C ] print dscp (tos) values \n"
	              "          [ -r value ] packets_per_sec \n"
	              "          [ -W test_name ] \n"
	              "          [ -T ] timestamp recv \n"
	      "          [ -h ] help \n",
              argv0, n, size);
      tests_show();
      exit(99);
}

int main(int argc, char *argv[])
{
  int error = 0;
  int c;
  if (argc < 2) {
    fprintf(stderr, "%s: starting server\n", argv[0]);
    server();
    return 0;
  }

  {
    /* client */
    int s;
    ssize_t r;
    struct msg *tm = (struct msg *) tbuf;
    struct msg *rm = (struct msg *) rbuf;

    struct addrinfo hints;
    struct addrinfo *result, *rp;
    struct addrinfo myaddr;

    char asciiport[16];

    /* summary of results */
    uint32_t consecutive = 0;
    uint32_t out_of_order = 0;
    uint32_t adjacent_dups = 0;
    uint32_t count = 0;
    uint32_t recent = 0;

    tm->size = 64;
    tm->n = 32;
    tm->cookie = getpid();

    while ((c = getopt(argc, argv, "fts:n:D:r:c:W:SEqdTCh?")) >= 0) {
      switch (c) {
      case 'f':
	tm->cmd = CMD_SEND;
	break;
      case 't':
	tm->cmd = CMD_SINK;
	break;
      case 'c':
	tm->n = sizetoi(optarg);
	break;
      case 'S':
	want_server = 1;
	break;
      case 's':
	tm->size = sizetoi(optarg);
	break;
      case 'q':
	quiet = 1;
	break;
      case 'd':
	dots = 1;
	break;
      case 'D':
	dscp = parse_ipqos(optarg);
	break;
      case 'E':
	ecn = 2;
	break;
      case 'C':
	want_tos = 1;
	break;
      case 'W':
	dscp_test = dscp_data(sweep = parse_sweep(optarg));
	break;
      case 'T':
	want_timestamps = 1;
	break;
      case 'r':
	packets_per_sec = atof(optarg);
	if (packets_per_sec < 0.001 || packets_per_sec > 1e6) {
	  fprintf(stderr, "%s: packets per sec (-r) must be 0.001..1000000\n",
		  argv[0]);
	  return 99;
      }
      break;
      case 'h':
      case '?':
      default:
	usage_and_die(argv[0], tm->n, tm->size);
	break;
      }
    }
  
    if(want_server) { exit(server()); }
 
    htonmsg(tm);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICSERV;
    hints.ai_protocol = 0;

    snprintf(asciiport, sizeof asciiport, "%d", PORT);
    
    if(optind >= argc) usage_and_die(argv[0],rm->n, rm->size);

    s = getaddrinfo(argv[optind], asciiport, &hints, &result);
    if (s != 0) {
      fprintf(stderr, "getaddrinfo: %s: %s\n", argv[optind], gai_strerror(s));
      exit(1);
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {

      s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (s < 0) {
        fprintf(stderr, "socket(%d, %d, %d) failed -- ",
                rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        perror("socket");
        continue;
      }

      r = connect(s, rp->ai_addr, rp->ai_addrlen);
      if (r == 0) /* success */
        break;
      perror("connect");
      close(s);
      /* continue */
    }

    if (rp == NULL) {
      fprintf(stderr, "unable to connect\n");
      exit(1);
    }

    myaddr.ai_addr = rp->ai_addr;
    myaddr.ai_addrlen = rp->ai_addrlen;
    myaddr.ai_family = rp->ai_family;

    freeaddrinfo(result);
    
  dscp |= ecn;

  if ( setsockopt( s, IPPROTO_IP, IP_TOS, &dscp, sizeof (dscp)) < 0 ) {
    perror( "setsockopt( IP_TOS )" );
  }

  /* request explicit congestion notification and dscp on received datagrams */

#ifdef IP_RECVTOS
  int tosflag = 1;
  socklen_t tosoptlen = sizeof( tosflag );
  if(myaddr.ai_family == AF_INET) {
    if ( setsockopt( s, IPPROTO_IP, IP_RECVTOS, &tosflag, tosoptlen ) < 0 ) {
      perror( "setsockopt( IP_RECVTOS )" );
    }
  }
#else
#warning NO IP_RECVTOS
#endif
#ifdef IPV6_RECVTCLASS
  if(myaddr.ai_family == AF_INET6) {
    if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVTCLASS, &tosflag, sizeof(tosflag)) < 0) {
      perror("IPV6_RECVTCLASS");
    }
  }
#else
#warning NO IPV6_RECVTCLASS
#endif

    r = send(s, tm, sizeof *tm, 0);
    if (r < 0) {
      pe("send");
    }
    if (r < (int) sizeof *tm) {
      fprintf(stderr, "send: short write (%d of %d)\n", (int) r, (int) sizeof *tm);
      exit(1);
    }

    ntohmsg(tm); /* swap some fields back so we can use them below */

    struct logger log[tm->n];
    memset(log,0, tm->n * sizeof(struct logger));
    do {

      struct pollfd ps = { .fd = s, .events = POLLIN };

      r = poll(&ps, 1, 500);

      struct msghdr header;
      struct iovec msg_iovec;
      int congestion_experienced = 0;
      char msg_control[ 1500 ];
      uint8_t *ecn_octet_p = NULL;

      /* receive source address */
      //  header.msg_name = &packet_remote_addr.sa;
      header.msg_namelen = sizeof( struct sockaddr_in6 );

      /* receive payload */
      msg_iovec.iov_base = rbuf;
      msg_iovec.iov_len = 1500;
      header.msg_iov = &msg_iovec;
      header.msg_iovlen = 1;

      /* receive explicit congestion notification */
      header.msg_control = msg_control;
      header.msg_controllen = 1500;

      /* receive flags */
      header.msg_flags = 0;

      if (ps.revents & POLLIN || ps.revents & POLLERR) {
        r = recvmsg(s, &header,  0);
        if (r < 0) {
          perror("recv");
	  if(++error > timeout) continue; else break;
        }
	
	struct cmsghdr *ecn_hdr = CMSG_FIRSTHDR( &header );
	if ( ecn_hdr
	     && ((ecn_hdr->cmsg_level == IPPROTO_IP)
		 && (ecn_hdr->cmsg_type == IP_TOS) 
		 || ((ecn_hdr->cmsg_level == IPPROTO_IPV6)
		     && ecn_hdr->cmsg_type == IPV6_TCLASS)))
	  {
	  ecn_octet_p = (uint8_t *)CMSG_DATA( ecn_hdr );
	  
	  if ( (*ecn_octet_p & 0x03) == 0x03 ) {
	    congestion_experienced = 1;
	  }
	}
	
        ntohmsg(rm);
#if 0
        printf("recv: %d - %08x %08x %08x %08x %08x\n", r,
               rm->magic, rm->cmd, rm->cookie, rm->n, rm->size);
        fflush(stdout);
#endif

        if (rm->magic != MAGIC) {
          fprintf(stderr, "wrong magic value\n");
          continue;
        }
        if (rm->cookie != tm->cookie) {
          fprintf(stderr, "wrong cookie value\n");
          continue;
        }
	if (rm->n < tm->n) {
		memcpy(&log[rm->n].msg,rm,sizeof(struct msg));
		if(ecn_octet_p != NULL) 
		  log[rm->n].tos = *ecn_octet_p;
		log[rm->n].arrival = arrivals++;
	}

	if(congestion_experienced)
	  ect_seen++;
        if (count > 0 && rm->n < recent)
          out_of_order++;
        if (count > 0 && rm->n == recent)
          adjacent_dups++;
        if (adjacent_dups == 0 && out_of_order == 0 && rm->n == consecutive)
          consecutive++;
        count++;
        recent = rm->n;
      }
      if (ps.revents & POLLHUP) {
        fprintf(stderr, "POLLHUP\n");
        error = 1;
      }
      if (ps.revents & POLLNVAL) {
        fprintf(stderr, "POLLNVAL\n");
        error = 1;
      }
      if (error) {
        fprintf(stderr, "ps.revents = %d\n", ps.revents);
        break;
      }
    } while (r > 0);

    if (count > 0 || error == 0) {
      printf("%d bytes -- received %d of %d -- %d consecutive %d ooo %d dups"
	     " %d ect\n",
	     tm->size, count, tm->n, consecutive, out_of_order, adjacent_dups,
	     ect_seen);
      if(dots) {
      for(int i = 0; i < tm->n; i++) {
	if(log[i].msg.n > 0) printf("."); else printf(" ");
	  if(i%72==0) printf("\n");
	}
      }

      if(want_tos) {
        int i,j;
        for(j = 0; j < tm->n; j++) {
      	  for(i = 0; i < tm->n; i++) {
		if(log[i].arrival == j) { 
			printf("%02x",log[i].tos); 
			break;
		}
	  }	
	if(i==tm->n) printf("  ");
	if(j%36==0) printf("\n");
	}
      }

      printf("\n");
    }

    /*end of client */
  }
  return error;
}
