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
 */

/*
 * A simple benchmark tool intended for long-term medium-transfer-rate
 * tests.  The idea is we send data at a fixed average rate, then measure
 * how often, how much, and for how long we depart from the average on the
 * receiving side.
 *
 * This is hopefully a good indicator of what kind of streaming video
 * quality you'd expect over a given link.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <memory.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAGIC 0x424c4f50                  // magic number for Request packets
#define SERVER_PORT 4947                  // port number to listen on
#define BUFSIZE (1024*1024)               // maximum chunk size to read/write
#define MIN_PERIODS_PER_SEC 10            // minimum chunks per sec to write
#define DROPOUT_MIN_USEC  (100*1000)      // print any dropout longer than this
#define CLOCK_RESET_USEC  (50*1000)       // ignore clock jumps more than this
#define MAX_CHILDREN 8                    // limit to this many connections
#define MAX_MBITS    1000                 // max speed per connection

#define _STR(n) #n
#define STR(n) _STR(n)


struct Request {
  uint32_t magic;     // magic number to reject bogus packets or wrong version
  int32_t megabits;   // requested data trasfer rate, in Mbits/sec
};


char buf[BUFSIZE];
int want_to_die;


static void sighandler_die(int sig) {
  want_to_die = 1;
}


// Returns the kernel monotonic timestamp in microseconds.
// This function never returns the value 0; it returns 1 instead, so that
// 0 can be used as a magic value.
#ifdef __MACH__  // MacOS X doesn't have clock_gettime()
#include <mach/mach.h>
#include <mach/mach_time.h>

static long long monotime(void) {
  static mach_timebase_info_data_t timebase;
  if (!timebase.denom) mach_timebase_info(&timebase);
  long long result = (mach_absolute_time() * timebase.numer /
                     timebase.denom / 1000);
  return !result ? 1 : result;
}
#else
static long long monotime(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
    perror("clock_gettime");
    exit(98); // really should never happen, so don't try to recover
  }
  long long result = ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
  return !result ? 1 : result;
}
#endif


static void usage_and_die(char *argv0) {
  fprintf(stderr,
          "\n"
          "Usage: %s                           (server mode)\n"
          "   or: %s <options...> <server-ip>  (client mode)\n"
          "\n"
          "      -b <Mbits/sec>  Mbits per second\n",
          argv0, argv0);
  exit(99);
}


// Render the given sockaddr as a string.  (Uses a static internal buffer
// which is overwritten each time.)
static const char *sockaddr_to_str(struct sockaddr *sa) {
  static char addrbuf[128];
  void *aptr;
  int port;

  switch (sa->sa_family) {
  case AF_INET:
    aptr = &((struct sockaddr_in *)sa)->sin_addr;
    port = ntohs(((struct sockaddr_in *)sa)->sin_port);
    break;
  case AF_INET6:
    aptr = &((struct sockaddr_in6 *)sa)->sin6_addr;
    port = ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
    break;
  default:
    return "unknown";
  }

  addrbuf[0] = '[';
  if (!inet_ntop(sa->sa_family, aptr, addrbuf + 1, sizeof(addrbuf) - 1)) {
    perror("inet_ntop");
    exit(98);
  }
  int addrlen = strlen(addrbuf);
  snprintf(addrbuf + addrlen, sizeof(addrbuf) - addrlen, "]:%d", port);
  return addrbuf;
}


static int do_select(int sock, long long usec_timeout) {
  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(sock, &rfds);
  struct timeval tv = {
    .tv_sec = usec_timeout / 1000000,
    .tv_usec = usec_timeout % 1000000,
  };
  return select(sock + 1, &rfds, NULL, NULL, usec_timeout >= 0 ? &tv : NULL);
}


void run_server(int conn, struct sockaddr_in6 *remoteaddr,
                socklen_t remoteaddr_len) {
  fprintf(stderr, "incoming connection from %s\n",
          sockaddr_to_str((struct sockaddr *)remoteaddr));

  struct Request req;
  ssize_t len = read(conn, &req, sizeof(req));
  if (len < 0) {
    perror("read(req)");
    return;
  } else if (len < (int)sizeof(req)) {
    fprintf(stderr, "read(req): short read (got %d bytes, expected %d)\n",
            (int)len, (int)sizeof(req));
    return;
  } else if (ntohl(req.magic) != MAGIC) {
    fprintf(stderr, "read(req): wrong magic (got %08X, expected %08X)\n",
            (int)ntohl(req.magic), MAGIC);
    return;
  }
  long megabits_per_sec = ntohl(req.megabits);
  fprintf(stderr, "client requested %ld megabits/sec\n", megabits_per_sec);
  if (megabits_per_sec < 0 || megabits_per_sec > MAX_MBITS) {
    fprintf(stderr, "megabits/sec (%ld) must be > 0 and < %d, aborting.\n",
            megabits_per_sec, MAX_MBITS);
    return;
  }

  if (shutdown(conn, SHUT_RD)) {
    perror("shutdown(RD)");
    return;
  }

  for (int i = 0; i < (int)(sizeof(buf)/sizeof(int)); i++) {
    ((int *)buf)[i] = random();
  }

  // The recipient will be expecting its input to arrive in equal-spaced
  // intervals.  It's cheating to send a giant block and then nothing
  // for a long time, although the average rate would technically be
  // the same.  So we have both a time-based and byte-based limit
  // on the amount of data in a single write.
  long long total = 0;
  long long bytes_per_period = megabits_per_sec * 1000000LL / 8
      / MIN_PERIODS_PER_SEC;
  if (bytes_per_period > 65536) bytes_per_period = 65536;

  long long start = monotime();

  while (!want_to_die) {
    // Note on calculations: megabits/sec * microseconds = bits
    long long now = monotime();
    long long goal = (now - start) * megabits_per_sec / 8;
    long long to_write = goal - total;
    if (to_write < bytes_per_period) {
      usleep((bytes_per_period - to_write) * 8 / megabits_per_sec);
      continue;
    }
    if (to_write > (int)sizeof(buf)) {
      to_write = sizeof(buf);
    }
    ssize_t wrote = write(conn, buf, to_write);
    if (wrote < 0) {
      perror("write");
      break;
    }
    total += wrote;
  }
}


int run_client(const char *remotename, long megabits_per_sec) {
  int sock = -1, ret = 1, alive = 0;
  struct addrinfo *ai = NULL;
  struct addrinfo hints = {
    .ai_flags = AI_ADDRCONFIG | AI_V4MAPPED,
    .ai_family = AF_INET6,
    .ai_socktype = SOCK_STREAM,
  };
  int err = getaddrinfo(remotename, STR(SERVER_PORT), &hints, &ai);
  if (err != 0 || !ai) {
    fprintf(stderr, "getaddrinfo(%s): %s\n", remotename, gai_strerror(err));
    return 1;
  }

  struct {
    long long disconnect_count;
    long long disconnect_usecs;
    long long drop_count;
    long long drop_maxdepth;
    long long drop_maxlength;
  } stats;
  memset(&stats, 0, sizeof(stats));

  long long start_time = 0, stop_time = 0, last_print_time = 0, now = 0;
  long long drop_start_time = 0, drop_depth = 0;
  long long total = 0, usec_offset = 0, last_usec_offset = 0;
  while (!want_to_die) {
    now = monotime();
    if (start_time) {
      long long expected_bytes = megabits_per_sec * (now - start_time) / 8;
      long long offset = total - expected_bytes;
      usec_offset = offset * 8 / megabits_per_sec;

      // Note: see long-winded explanation ("the subtle part") below
      // for why we expect the offset to be positive/negative.
      if (usec_offset < 0 && last_usec_offset >= 0) {
        // network quality has dropped out.
        // For this dropout, we want to track both the depth (how many
        // seconds we fell behind, in total, and thus need to catch up)
        // as well as the length (how long it took to get back to
        // normal).  Using a combination of the two, we can
        // calculate how much buffer space would be needed for a
        // particular reliability level, given that dropouts
        // may overlap (a new one begins before we recovered from
        // the last one).
        //
        // (For our purposes, drop_depth is always negative and
        // drop_length is always positive.  Making depth negative
        // is not really that important, but it makes it easy
        // to tell them apart when you print them.)
        drop_start_time = now;
        drop_depth = 0;
      } else if (usec_offset >= 0 && last_usec_offset < 0) {
        // dropout is over - we've caught up again
        long long drop_length = now - drop_start_time;
        int interesting = drop_length >= DROPOUT_MIN_USEC;
        if (stats.drop_maxlength < drop_length) {
          stats.drop_maxlength = drop_length;
          interesting = 1;
        }
        if (stats.drop_maxdepth > drop_depth) {
          stats.drop_maxdepth = drop_depth;
          interesting = 1;
        }
        if (interesting) {
          stats.drop_count++;
          printf("dropout: %.3fs/%.3fs\n",
                 drop_length / 1e6,
                 drop_depth / 1e6);
        }
        drop_start_time = 0;
      }
      if (usec_offset < drop_depth) {
        drop_depth = usec_offset;
      }
      last_usec_offset = usec_offset;

      if (now - last_print_time >= 1000000) {
        printf("%11.3fs %ldMbps offset=%.3fs disconn=%lld/%.3fs "
               "drops=%lld/%.3fs/%.3fs\n",
               (now - start_time) / 1e6,
               megabits_per_sec,
               (usec_offset + stats.disconnect_usecs) / 1e6,
               stats.disconnect_count,
               (stats.disconnect_usecs +
                (stop_time ? now - stop_time : 0)) / 1e6,
               stats.drop_count,
               stats.drop_maxlength / 1e6,
               stats.drop_maxdepth / 1e6);
        last_print_time = now;
      }
    }

    if (sock < 0) {
      sock = socket(PF_INET6, SOCK_STREAM, 0);
      if (sock < 0) {
        perror("socket");
        goto error;
      }

      fprintf(stderr, "connecting to %s...\n", sockaddr_to_str(ai->ai_addr));
      if (connect(sock, ai->ai_addr, ai->ai_addrlen) != 0) {
        perror("connect");
        goto reopen;
      }

      now = monotime();
      last_print_time = 0;

      struct Request req = {
        .magic = htonl(MAGIC),
        .megabits = htonl(megabits_per_sec),
      };
      if (write(sock, &req, sizeof(req)) != sizeof(req)) {
        perror("write");
        goto reopen;
      }
      if (shutdown(sock, SHUT_WR)) {
        perror("shutdown(WR)");
        goto reopen;
      }
      alive = 1;
    }

    now = monotime();
    long long delay = start_time
        ? 1000000 - ((now - start_time) % 1000000)
        : 1000000;
    int nfds = do_select(sock, delay > 0 ? delay : 0);
    if (nfds < 0 && errno != EINTR) {
      perror("select");
      goto reopen;
    }

    if (nfds > 0) {
      ssize_t len = read(sock, buf, sizeof(buf));
      now = monotime();

      /*
       * This is the subtle part:
       *
       * We count the start time as of when we *receive* the first *data*,
       * not just the time we connect.  As of that moment, we know that
       * the other end has definitely sent us a fairly big chunk of data,
       * so we'll be able to read at least several packets' worth right
       * away.  This means we start off ahead of schedule, with more bytes
       * than we mathematically expect at time zero.
       *
       * From that moment onward, we should be getting exactly the right
       * number of megabits_per_sec, except for minor network variations,
       * which is what we want to measure.  If it does fall behind, it should
       * catch up again shortly after, and vice versa.
       *
       * Because of the way this works, our average position should always
       * be slightly > the goal, which means if we ever fall behind the
       * goal even by a little, we definitely experienced a network
       * problem.
       *
       * This method of measurement should match what actually happens when
       * streaming live media: when deciding how much you need to buffer
       * locally before starting playback, you start counting from the moment
       * you receive the first byte, because that's the first moment you
       * could ever consider starting to play back.
       */
      if (!start_time) {
        start_time = last_print_time = now;
      }

      /*
       * We count TCP disconnects separately from other kinds of network
       * outages.  The "disconnected time" is considered to be from
       * the moment we stop receiving data, up to the moment we start
       * receiving data again.
       */
      if (stop_time) {
        stats.disconnect_usecs += now - stop_time;
        stop_time = 0;
      }

      if (len < 0) {
        perror("read");
        goto reopen;
      } else if (len == 0) {
        fprintf(stderr, "received EOF\n");
        goto reopen;
      } else {
        total += len;
      }
    }

    continue;
reopen:
    if (alive) {
      stop_time = now;
      stats.disconnect_count++;
      alive = 0;
    }
    fprintf(stderr, "retrying connection...\n");
    sleep(1);
    close(sock);
    sock = -1;
  }

  ret = 0;
error:
  if (ai) freeaddrinfo(ai);
  return ret;
}


int main(int argc, char **argv) {
  struct sockaddr_in6 listenaddr, remoteaddr;
  socklen_t remoteaddr_len;
  int sock = -1;
  int megabits_per_sec = 0;

  int c;
  while ((c = getopt(argc, argv, "b:h?")) >= 0) {
    switch (c) {
    case 'b':
      megabits_per_sec = atoi(optarg);
      if (megabits_per_sec > MAX_MBITS || megabits_per_sec < 1) {
        fprintf(stderr, "%s: megabits per second must be >= 0 and < %d\n",
                argv[0], MAX_MBITS);
        return 99;
      }
      break;
    case 'h':
    case '?':
    default:
      usage_and_die(argv[0]);
      break;
    }
  }

  struct sigaction act = {
    .sa_handler = sighandler_die,
    .sa_flags = SA_RESETHAND,
  };
  sigaction(SIGINT, &act, NULL);
  signal(SIGPIPE, SIG_IGN);

  if (argc - optind == 0) {
    fprintf(stderr, "server mode.\n");

    sock = socket(PF_INET6, SOCK_STREAM, 0);
    if (sock < 0) {
      perror("socket");
      return 1;
    }

    int reuseval = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                   &reuseval, sizeof(reuseval)) < 0) {
      perror("setsockopt(SO_REUSEADDR)");
      return 1;
    }

    memset(&listenaddr, 0, sizeof(listenaddr));
    listenaddr.sin6_family = AF_INET6;
    listenaddr.sin6_port = htons(SERVER_PORT);
    if (bind(sock, (struct sockaddr *)&listenaddr, sizeof(listenaddr)) != 0) {
      perror("bind");
      return 1;
    }
    socklen_t addrlen = sizeof(listenaddr);
    if (getsockname(sock, (struct sockaddr *)&listenaddr, &addrlen) != 0) {
      perror("getsockname");
      return 1;
    }
    if (listen(sock, 1)) {
      perror("listen");
      return 1;
    }
    fprintf(stderr, "server listening at %s\n",
           sockaddr_to_str((struct sockaddr *)&listenaddr));

    int numchildren = 0;
    while (!want_to_die) {
      int nfds;

      if (numchildren < MAX_CHILDREN) {
        nfds = do_select(sock, numchildren ? 1000*1000 : -1);
      } else {
        if (waitpid(-1, NULL, 0) > 0) {
          numchildren--;
        }
        nfds = 0;
      }
      while (waitpid(-1, NULL, WNOHANG) > 0) {
        numchildren--;
      }
      if (nfds > 0) {
        remoteaddr_len = sizeof(remoteaddr);
        int conn = accept(sock, (struct sockaddr *)&remoteaddr,
                          &remoteaddr_len);
        if (conn < 0) {
          perror("accept");
          continue;
        }
        pid_t pid = fork();
        if (pid < 0) {
          perror("fork");
          sleep(1);
          close(conn);
        } else if (pid > 0) {
          // parent
          close(conn);
          numchildren++;
        } else {
          // child
          close(sock);
          run_server(conn, &remoteaddr, remoteaddr_len);
          fprintf(stderr, "client disconnected.\n");
          _exit(0);
        }
      }
    }
  } else if (argc - optind == 1) {
    fprintf(stderr, "client mode.\n");

    if (!megabits_per_sec) {
      fprintf(stderr, "%s: must specify -b in client mode\n", argv[0]);
      usage_and_die(argv[0]);
    }

    const char *remotename = argv[optind];
    return run_client(remotename, megabits_per_sec);
  } else {
    // wrong number of arguments
    usage_and_die(argv[0]);
  }

  if (sock >= 0) close(sock);
  return 0;
}
