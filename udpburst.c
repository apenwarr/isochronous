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

#define PORT 19289

#define MAGIC 0x31f71dc1

struct msg {
  u_int32_t magic;
  u_int32_t cmd;
#define CMD_SEND 1
#define CMD_SINK 2
  u_int32_t cookie;
  u_int32_t n;
  u_int32_t size;
};

struct logger {
  struct msg msg;
  struct timeval ts;
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

void server(void)
{
  int s, r;
  struct sockaddr_in6 sa, rsa;

  s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (s < 1) pe("socket");

  sa.sin6_family = AF_INET6;
  sa.sin6_port = htons(PORT);
  sa.sin6_flowinfo = 0;
  sa.sin6_addr = in6addr_any;
  sa.sin6_scope_id = 0;

  r = bind(s, (struct sockaddr *) &sa, sizeof sa);
  if (r < 0) pe("bind");

  do {
    struct msg *rm = (struct msg *) rbuf;
    struct msg *tm = (struct msg *) tbuf;
    u_int32_t i;
    socklen_t rsa_len = sizeof rsa;

    r = recvfrom(s, rbuf, sizeof rbuf, 0, (struct sockaddr *) &rsa, &rsa_len);
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

    for  (i = 0; i < rm->n; i++) {
      tm->n = htonl(i);
      r = sendto(s, tbuf, rm->size, 0, (struct sockaddr *) &rsa, rsa_len);
      if (r < 0) pe("sendto");
      if (r < (int) rm->size)
        fprintf(stderr, "short sendto (expected %d, got %d)\n", rm->size, r);
    }
  } while (1);
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


int main(int argc, char *argv[])
{
  int error = 0;
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

    char asciiport[16];

    /* summary of results */
    unsigned int consecutive = 0;
    unsigned int out_of_order = 0;
    unsigned int adjacent_dups = 0;
    unsigned int count = 0;
    unsigned int recent = 0;

    tm->size = 64;
    tm->n = 32;
    tm->cookie = getpid();

    if (argc < 3) {
    usage:
      fprintf(stderr, "usage: %s from host [number] [msgsize]\n", argv[0]);
#if 0
      fprintf(stderr, "    or %s to host [number] [msgsize]\n", argv[0]);
#endif
      fprintf(stderr, "   default number = %d, default msgsize = %d\n",
              tm->n, tm->size);
      exit(1);
    }
    if (strcmp(argv[1], "from") == 0) {
      tm->cmd = CMD_SEND;
#if 0
    } else if (strcmp(argv[1], "to") == 0) {
      tm->cmd = CMD_SINK;
#endif
    } else
      goto usage;

    if (argc > 3)
      tm->n = sizetoi(argv[3]);
    if (argc > 4)
      tm->size = sizetoi(argv[4]);

    htonmsg(tm);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICSERV;
    hints.ai_protocol = 0;

    snprintf(asciiport, sizeof asciiport, "%d", PORT);

    s = getaddrinfo(argv[2], asciiport, &hints, &result);
    if (s != 0) {
      fprintf(stderr, "getaddrinfo: %s: %s\n", argv[2], gai_strerror(s));
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

    freeaddrinfo(result);

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
    memset(log,0,tm->n * sizeof(struct logger));
    do {

      struct pollfd ps = { .fd = s, .events = POLLIN };

      r = poll(&ps, 1, 500);

      if (ps.revents & POLLIN || ps.revents & POLLERR) {
        r = recv(s, rbuf, sizeof rbuf, 0);
        if (r < 0) {
          perror("recv");
	  error = 1;
	  break;
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
	}
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
      printf("%d bytes -- received %d of %d -- %d consecutive %d ooo %d dups\n",
	     tm->size, count, tm->n, consecutive, out_of_order, adjacent_dups);
      for(int i = 0; i < tm->n; i++) {
	if(log[i].msg.n > 0) printf("."); else printf(" ");
	  if(i%72==0) printf("\n");
	}
      printf("\n");
    }

    /*end of client */
  }
  return error;
}
