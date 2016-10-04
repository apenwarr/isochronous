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
 *
 * Like ping, but sends packets isochronously (equally spaced in time) in
 * each direction.  By being clever, we can use the known timing of each
 * packet to determine, on a noisy network, which direction is dropping or
 * delaying packets and by how much.
 *
 * Also unlike ping, this requires a server (ie. another copy of this
 * program) to be running on the remote end.
 */
#include "isoping.h"

#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <memory.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW 4
#endif

#define MAGIC 0x424c4950
#define SERVER_PORT 4948
#define DEFAULT_PACKETS_PER_SEC 10.0
#define DEFAULT_TTL 2

// A 'cycle' is the amount of time we can assume our calibration between
// the local and remote monotonic clocks is reasonably valid.  It seems
// some of our devices have *very* fast clock skew (> 1 msec/minute) so
// this unfortunately has to be much shorter than I'd like.  This may
// reflect actual bugs in our ntpd and/or the kernel's adjtime()
// implementation.  In particular, we shouldn't have to do this kind of
// periodic correction, because that's what adjtime() *is*.  But the results
// are way off without this.
#define USEC_PER_CYCLE (10*1000*1000)

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define DIFF(x, y) ((int32_t)((uint32_t)(x) - (uint32_t)(y)))
#define DIV(x, y) ((y) ? ((double)(x)/(y)) : 0)
#define _STR(n) #n
#define STR(n) _STR(n)

// Global flag values.
int is_server = 1;
int quiet = 0;
int ttl = DEFAULT_TTL;
int want_timestamps = 0;
double packets_per_sec = DEFAULT_PACKETS_PER_SEC;
double prints_per_sec = -1.0;

int want_to_die;


static void sighandler(int sig) {
  want_to_die = 1;
}

Session::Session(uint32_t now)
    : usec_per_pkt(1e6 / packets_per_sec),
      usec_per_print(prints_per_sec > 0 ? 1e6 / prints_per_sec : 0),
      next_tx_id(1),
      next_rx_id(0),
      next_rxack_id(0),
      start_rtxtime(0),
      start_rxtime(0),
      last_rxtime(0),
      min_cycle_rxdiff(0),
      next_cycle(0),
      next_send(now + usec_per_pkt),
      num_lost(0),
      next_txack_index(0),
      last_print(now - usec_per_pkt),
      lat_tx(0), lat_tx_min(0x7fffffff), lat_tx_max(0),
      lat_tx_count(0), lat_tx_sum(0), lat_tx_var_sum(0),
      lat_rx(0), lat_rx_min(0x7fffffff), lat_rx_max(0),
      lat_rx_count(0), lat_rx_sum(0), lat_rx_var_sum(0) {
  memset(&tx, 0, sizeof(tx));
  strcpy(last_ackinfo, "");
}

// Returns the kernel monotonic timestamp in microseconds, truncated to
// 32 bits.  That will wrap around every ~4000 seconds, which is okay
// for our purposes.  We use 32 bits to save space in our packets.
// This function never returns the value 0; it returns 1 instead, so that
// 0 can be used as a magic value.
#ifdef __MACH__  // MacOS X doesn't have clock_gettime()
#include <mach/mach.h>
#include <mach/mach_time.h>

static uint64_t ustime64(void) {
  static mach_timebase_info_data_t timebase;
  if (!timebase.denom) mach_timebase_info(&timebase);
  uint64_t result = (mach_absolute_time() * timebase.numer /
                     timebase.denom / 1000);
  return !result ? 1 : result;
}
#else
static uint64_t ustime64(void) {
  // CLOCK_MONOTONIC_RAW, when available, is not subject to NTP speed
  // adjustments while CLOCK_MONOTONIC is.  You might expect NTP speed
  // adjustments to make things better if we're trying to sync timings
  // between two machines, but at least our ntpd is pretty bad at making
  // adjustments, so it tends the vary the speed wildly in order to kind
  // of oscillate around the right time.  Experimentally, CLOCK_MONOTONIC_RAW
  // creates less trouble for isoping's use case.
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) < 0) {
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
      perror("clock_gettime");
      exit(98); // really should never happen, so don't try to recover
    }
  }
  uint64_t result = ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
  return !result ? 1 : result;
}
#endif


static uint32_t ustime(void) {
  return (uint32_t)ustime64();
}


static void usage_and_die(char *argv0) {
  fprintf(stderr,
          "\n"
          "Usage: %s                          (server mode)\n"
          "   or: %s <server-hostname-or-ip>  (client mode)\n"
          "\n"
          "      -f <lines/sec>  max output lines per second\n"
          "      -r <pps>        packets per second (default=%g)\n"
          "      -t <ttl>        packet ttl to use (default=2 for safety)\n"
          "      -q              quiet mode (don't print packets)\n"
          "      -T              print timestamps\n",
          argv0, argv0, (double)DEFAULT_PACKETS_PER_SEC);
  exit(99);
}


// Render the given sockaddr as a string.  (Uses a static internal buffer
// which is overwritten each time.)
static const char *sockaddr_to_str(struct sockaddr *sa) {
  static char addrbuf[128];
  void *aptr;

  switch (sa->sa_family) {
  case AF_INET:
    aptr = &((struct sockaddr_in *)sa)->sin_addr;
    break;
  case AF_INET6:
    aptr = &((struct sockaddr_in6 *)sa)->sin6_addr;
    break;
  default:
    return "unknown";
  }

  if (!inet_ntop(sa->sa_family, aptr, addrbuf, sizeof(addrbuf))) {
    perror("inet_ntop");
    exit(98);
  }
  return addrbuf;
}


// Print the timestamp corresponding to the current time.
// Deliberately the same format as tcpdump uses, so we can easily sort and
// correlate messages between isoping and tcpdump.
static void print_timestamp(uint32_t when) {
  uint64_t now = ustime64();
  int32_t nowdiff = DIFF(now, when);
  uint64_t when64 = now - nowdiff;
  time_t t = when64 / 1000000;
  struct tm tm;
  memset(&tm, 0, sizeof(tm));
  localtime_r(&t, &tm);
  printf("%02d:%02d:%02d.%06d ", tm.tm_hour, tm.tm_min, tm.tm_sec,
         (int)(when64 % 1000000));
}


static double onepass_stddev(long long sumsq, long long sum, long long count) {
  // Incremental standard deviation calculation, without needing to know the
  // mean in advance.  See:
  // http://mathcentral.uregina.ca/QQ/database/QQ.09.02/carlos1.html
  long long numer = (count * sumsq) - (sum * sum);
  long long denom = count * (count - 1);
  return sqrt(DIV(numer, denom));
}


void prepare_tx_packet(struct Session *s) {
  s->tx.magic = htonl(MAGIC);
  s->tx.id = htonl(s->next_tx_id++);
  s->tx.usec_per_pkt = htonl(s->usec_per_pkt);
  s->tx.txtime = htonl(s->next_send);
  s->tx.clockdiff = s->start_rtxtime ?
      htonl(s->start_rxtime - s->start_rtxtime) : 0;
  s->tx.num_lost = htonl(s->num_lost);
  s->tx.first_ack = htonl(s->next_txack_index);
}

static int send_packet(struct Session *s,
                       int sock,
                       struct sockaddr *remoteaddr,
                       socklen_t remoteaddr_len) {
  // note: tx.acks[] is filled in incrementally; we just transmit the current
  // state of it here.  The reason we keep a list of the most recent acks is in
  // case our packet gets lost, so the receiver will have more chances to
  // receive the timing information for the packets it sent us.
  if (is_server) {
    if (sendto(sock, &s->tx, sizeof(s->tx), 0,
               remoteaddr, remoteaddr_len) < 0) {
      perror("sendto");
    }
  } else {
    if (send(sock, &s->tx, sizeof(s->tx), 0) < 0) {
      int e = errno;
      perror("send");
      if (e == ECONNREFUSED) return 2;
    }
  }
  s->next_send += s->usec_per_pkt;
  return 0;
}


void handle_packet(struct Session *s, uint32_t now) {
  // process the incoming packet header.
  // Most of the complexity here comes from the fact that the remote
  // system's clock will be skewed vs. ours.  (We use CLOCK_MONOTONIC
  // instead of CLOCK_REALTIME, so unless we figure out the skew offset,
  // it's essentially meaningless to compare the two values.)  We can
  // however assume that both clocks are ticking at 1 microsecond per
  // tick... except for inevitable clock rate errors, which we have to
  // account for occasionally.

  uint32_t txtime = ntohl(s->rx.txtime), rxtime = now;
  uint32_t id = ntohl(s->rx.id);
  if (!s->next_rx_id) {
    // The remote txtime is told to us by the sender, so it is always perfectly
    // correct... but it uses the sender's clock.
    s->start_rtxtime = txtime - id * s->usec_per_pkt;

    // The receive time uses our own clock and is estimated by us, so it needs
    // to be corrected over time because:
    //   a) the two clocks inevitably run at slightly different speeds;
    //   b) there's an unknown, variable, network delay between tx and rx.
    // Here, we're just assigning an initial estimate.
    s->start_rxtime = rxtime - id * s->usec_per_pkt;

    s->min_cycle_rxdiff = 0;
    s->next_rx_id = id;
    s->next_cycle = now + USEC_PER_CYCLE;
  }

  // see if we missed receiving any previous packets.
  int32_t tmpdiff = DIFF(id, s->next_rx_id);
  if (tmpdiff > 0) {
    // arriving packet has id > expected, so something was lost.
    // Note that we don't use the rx.acks[] structure to determine packet loss;
    // that's because the limited size of the array means that, during a longer
    // outage, we might not see an ack for a packet *even if that packet arrived
    // safely* at the remote.  So we count on the remote end to count its own
    // packet losses using sequence numbers, and send that count back to us.  We
    // do the same here for incoming packets from the remote, and send the error
    // count back to them next time we're ready to transmit.
    fprintf(stderr, "lost %ld  expected=%ld  got=%ld\n",
            (long)tmpdiff, (long)s->next_rx_id, (long)id);
    s->num_lost += tmpdiff;
    s->next_rx_id += tmpdiff + 1;
  } else if (!tmpdiff) {
    // exactly as expected; good.
    s->next_rx_id++;
  } else if (tmpdiff < 0) {
    // packet before the expected one? weird.
    fprintf(stderr, "out-of-order packets? %ld\n", (long)tmpdiff);
  }

  // fix up the clock offset if there's any drift.
  tmpdiff = DIFF(rxtime, s->start_rxtime + id * s->usec_per_pkt);
  if (tmpdiff < -20) {
    // packet arrived before predicted time, so prediction was based on
    // a packet that was "slow" before, or else one of our clocks is
    // drifting. Use earliest legitimate start time.
    fprintf(stderr, "time paradox: backsliding start by %ld usec\n",
            (long)tmpdiff);
    s->start_rxtime = rxtime - id * s->usec_per_pkt;
  }
  int32_t rxdiff = DIFF(rxtime, s->start_rxtime + id * s->usec_per_pkt);

  // Figure out the offset between our clock and the remote's clock, so we can
  // calculate the minimum round trip time (rtt). Then, because the consecutive
  // packets sent in both directions are equally spaced in time, we can figure
  // out how much a particular packet was delayed in transit - independently in
  // each direction! This is an advantage over the normal "ping" program which
  // has no way to tell which direction caused the delay, or which direction
  // dropped the packet.

  // Our clockdiff is
  //   (our rx time) - (their tx time)
  //   == (their rx time + offset) - (their tx time)
  //   == (their tx time + offset + 1/2 rtt) - (their tx time)
  //   == offset + 1/2 rtt
  // and theirs (rx.clockdiff) is:
  //   (their rx time) - (our tx time)
  //   == (their rx time) - (their tx time + offset)
  //   == (their tx time + 1/2 rtt) - (their tx time + offset)
  //   == 1/2 rtt - offset
  // So add them together and we get:
  //   offset + 1/2 rtt + 1/2 rtt - offset
  //   == rtt
  // Subtract them and we get:
  //   offset + 1/2 rtt - 1/2 rtt + offset
  //   == 2 * offset
  // ...but that last subtraction is dangerous because if we divide by 2 to get
  // offset, it doesn't work with 32-bit math, which may have discarded a
  // high-order bit somewhere along the way.  Instead, we can extract offset
  // once we have rtt by substituting it into
  //   clockdiff = offset + 1/2 rtt
  //   offset = clockdiff - 1/2 rtt
  // (Dividing rtt by 2 is safe since it's always small and positive.)
  //
  // (This example assumes 1/2 rtt in each direction. There's no way to
  // determine it more accurately than that.)
  int32_t clockdiff = DIFF(s->start_rxtime, s->start_rtxtime);
  int32_t rtt = clockdiff + ntohl(s->rx.clockdiff);
  int32_t offset = DIFF(clockdiff, rtt / 2);
  if (!ntohl(s->rx.clockdiff)) {
    // don't print the first packet: it has an invalid clockdiff since the
    // client can't calculate the clockdiff until it receives at least one
    // packet from us.
    s->last_print = now - s->usec_per_print + 1;
  } else {
    // not the first packet, so statistics are valid.
    s->lat_rx_count++;
    s->lat_rx = rxdiff + rtt/2;
    s->lat_rx_min = s->lat_rx_min > s->lat_rx ? s->lat_rx : s->lat_rx_min;
    s->lat_rx_max = s->lat_rx_max < s->lat_rx ? s->lat_rx : s->lat_rx_max;
    s->lat_rx_sum += s->lat_rx;
    s->lat_rx_var_sum += s->lat_rx * s->lat_rx;
  }

  // Note: the way ok_to_print is structured, if there is a dropout in the
  // connection for more than usec_per_print, we will statistically end up
  // printing the first packet after the dropout ends.  That one should have the
  // longest timeout, ie. a "worst case" packet, which is usually the
  // information you want to see.
  int ok_to_print = !quiet && DIFF(now, s->last_print) >= s->usec_per_print;
  if (ok_to_print) {
    if (want_timestamps) print_timestamp(rxtime);
    printf("%12s  %6.1f ms rx  (min=%.1f)  loss: %ld/%ld tx  %ld/%ld rx\n",
           s->last_ackinfo,
           (rxdiff + rtt/2) / 1000.0,
           (rtt/2) / 1000.0,
           (long)ntohl(s->rx.num_lost),
           (long)s->next_tx_id - 1,
           (long)s->num_lost,
           (long)s->next_rx_id - 1);
    s->last_ackinfo[0] = '\0';
    s->last_print = now;
  }

  if (rxdiff < s->min_cycle_rxdiff) s->min_cycle_rxdiff = rxdiff;
  if (DIFF(now, s->next_cycle) >= 0) {
    if (s->min_cycle_rxdiff > 0) {
      fprintf(stderr, "clock skew: sliding start by %ld usec\n",
              (long)s->min_cycle_rxdiff);
      s->start_rxtime += s->min_cycle_rxdiff;
    }
    s->min_cycle_rxdiff = 0x7fffffff;
    s->next_cycle += USEC_PER_CYCLE;
  }

  // schedule this for an ack next time we send the packet
  s->tx.acks[s->next_txack_index].id = htonl(id);
  s->tx.acks[s->next_txack_index].rxtime = htonl(rxtime);
  s->next_txack_index = (s->next_txack_index + 1) % ARRAY_LEN(s->tx.acks);

  // see which of our own transmitted packets have been acked
  uint32_t first_ack = ntohl(s->rx.first_ack);
  for (uint32_t i = 0; i < ARRAY_LEN(s->rx.acks); i++) {
    uint32_t acki = (first_ack + i) % ARRAY_LEN(s->rx.acks);
    uint32_t ackid = ntohl(s->rx.acks[acki].id);
    if (!ackid) continue;  // empty slot
    if (DIFF(ackid, s->next_rxack_id) >= 0) {
      // an expected ack
      uint32_t start_txtime = s->next_send - s->next_tx_id * s->usec_per_pkt;
      uint32_t txtime = start_txtime + ackid * s->usec_per_pkt;
      uint32_t rrxtime = ntohl(s->rx.acks[acki].rxtime);
      uint32_t rxtime = rrxtime + offset;
      // note: already contains 1/2 rtt, unlike rxdiff
      int32_t txdiff = DIFF(rxtime, txtime);
      if (s->usec_per_print <= 0 && s->last_ackinfo[0]) {
        // only print multiple acks per rx if no usec_per_print limit
        if (want_timestamps) print_timestamp(rxtime);
        printf("%12s\n", s->last_ackinfo);
        s->last_ackinfo[0] = '\0';
      }
      if (!s->last_ackinfo[0]) {
        snprintf(s->last_ackinfo, sizeof(s->last_ackinfo), "%6.1f ms tx",
                 txdiff / 1000.0);
      }
      s->next_rxack_id = ackid + 1;
      s->lat_tx_count++;
      s->lat_tx = txdiff;
      s->lat_tx_min = s->lat_tx_min > s->lat_tx ? s->lat_tx : s->lat_tx_min;
      s->lat_tx_max = s->lat_tx_max < s->lat_tx ? s->lat_tx : s->lat_tx_max;
      s->lat_tx_sum += s->lat_tx;
      s->lat_tx_var_sum += s->lat_tx * s->lat_tx;
    }
  }

  s->last_rxtime = rxtime;
}


int isoping_main(int argc, char **argv) {
  struct sockaddr_in6 listenaddr, rxaddr, last_rxaddr;
  struct sockaddr *remoteaddr = NULL;
  socklen_t remoteaddr_len = 0, rxaddr_len = 0;
  struct addrinfo *ai = NULL;
  int sock = -1;

  setvbuf(stdout, NULL, _IOLBF, 0);

  int c;
  while ((c = getopt(argc, argv, "f:r:t:qTh?")) >= 0) {
    switch (c) {
    case 'f':
      prints_per_sec = atof(optarg);
      if (prints_per_sec <= 0) {
        fprintf(stderr, "%s: lines per second must be >= 0\n", argv[0]);
        return 99;
      }
      break;
    case 'r':
      packets_per_sec = atof(optarg);
      if (packets_per_sec < 0.001 || packets_per_sec > 1e6) {
        fprintf(stderr, "%s: packets per sec (-r) must be 0.001..1000000\n",
                argv[0]);
        return 99;
      }
      break;
    case 't':
      ttl = atoi(optarg);
      if (ttl < 1) {
        fprintf(stderr, "%s: ttl must be >= 1\n", argv[0]);
        return 99;
      }
      break;
    case 'q':
      quiet = 1;
      break;
    case 'T':
      want_timestamps = 1;
      break;
    case 'h':
    case '?':
    default:
      usage_and_die(argv[0]);
      break;
    }
  }

  sock = socket(PF_INET6, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("socket");
    return 1;
  }

  if (argc - optind == 0) {
    is_server = 1;
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
    fprintf(stderr, "server listening at [%s]:%d\n",
           sockaddr_to_str((struct sockaddr *)&listenaddr),
           ntohs(listenaddr.sin6_port));
  } else if (argc - optind == 1) {
    const char *remotename = argv[optind];
    is_server = 0;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_ADDRCONFIG | AI_V4MAPPED;
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    int err = getaddrinfo(remotename, STR(SERVER_PORT), &hints, &ai);
    if (err != 0 || !ai) {
      fprintf(stderr, "getaddrinfo(%s): %s\n", remotename, gai_strerror(err));
      return 1;
    }
    fprintf(stderr, "connecting to %s...\n", sockaddr_to_str(ai->ai_addr));
    if (connect(sock, ai->ai_addr, ai->ai_addrlen) != 0) {
      perror("connect");
      return 1;
    }
    remoteaddr = ai->ai_addr;
    remoteaddr_len = ai->ai_addrlen;
  } else {
    usage_and_die(argv[0]);
  }

  fprintf(stderr, "using ttl=%d\n", ttl);
  // IPPROTO_IPV6 is the only one that works on MacOS, and is arguably the
  // technically correct thing to do since it's an AF_INET6 socket.
  if (setsockopt(sock, IPPROTO_IPV6, IP_TTL, &ttl, sizeof(ttl))) {
    perror("setsockopt(TTLv6)");
    return 1;
  }
  // ...but in Linux (at least 3.13), IPPROTO_IPV6 does not actually
  // set the TTL if the IPv6 socket ends up going over IPv4.  We have to
  // set that separately.  On MacOS, that always returns EINVAL, so ignore
  // the error if that happens.
  if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl))) {
    if (errno != EINVAL) {
      perror("setsockopt(TTLv4)");
      return 1;
    }
  }

  uint32_t now = ustime();       // current time

  struct sigaction act;
  memset(&act, 0, sizeof(act));
  act.sa_handler = sighandler;
  act.sa_flags = SA_RESETHAND;
  sigaction(SIGINT, &act, NULL);

  struct Session s(now);

  while (!want_to_die) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    struct timeval tv;
    tv.tv_sec = 0;

    now = ustime();
    if (DIFF(s.next_send, now) < 0) {
      tv.tv_usec = 0;
    } else {
      tv.tv_usec = DIFF(s.next_send, now);
    }
    int nfds = select(sock + 1, &rfds, NULL, NULL, remoteaddr ? &tv : NULL);
    now = ustime();
    if (nfds < 0 && errno != EINTR) {
      perror("select");
      return 1;
    }

    // time to send the next packet?
    if (remoteaddr && DIFF(now, s.next_send) >= 0) {
      prepare_tx_packet(&s);
      int err = send_packet(&s, sock, remoteaddr, remoteaddr_len);
      if (err != 0) {
        return err;
      }
      // TODO(pmccurdy): Track disconnections across multiple clients.  Use
      // recvmsg with the MSG_ERRQUEUE flag to detect connection refused.
      if (is_server && DIFF(now, s.last_rxtime) > 60*1000*1000) {
        fprintf(stderr, "client disconnected.\n");
        remoteaddr = NULL;
      }
    }

    if (nfds > 0) {
      // incoming packet
      rxaddr_len = sizeof(rxaddr);
      ssize_t got = recvfrom(sock, &s.rx, sizeof(s.rx), 0,
                             (struct sockaddr *)&rxaddr, &rxaddr_len);
      if (got < 0) {
        int e = errno;
        perror("recvfrom");
        if (!is_server && e == ECONNREFUSED) return 2;
        continue;
      }
      if (got != sizeof(s.rx) || s.rx.magic != htonl(MAGIC)) {
        fprintf(stderr, "got invalid packet of length %ld\n", (long)got);
        continue;
      }

      // is it a new client?
      if (is_server) {
        // TODO(pmccurdy): Maintain a hash table of Sessions, look up based
        // on rxaddr, create a new one if necessary, remove this resetting code.
        if (!remoteaddr ||
            memcmp(&rxaddr, &last_rxaddr, sizeof(rxaddr)) != 0) {
          fprintf(stderr, "new client connected: %s\n",
                  sockaddr_to_str((struct sockaddr *)&rxaddr));
          memcpy(&last_rxaddr, &rxaddr, sizeof(rxaddr));
          remoteaddr = (struct sockaddr *)&last_rxaddr;
          remoteaddr_len = rxaddr_len;

          s.next_send = now + 10*1000;
          s.next_tx_id = 1;
          s.next_rx_id = s.next_rxack_id = 0;
          s.start_rtxtime = s.start_rxtime = 0;
          s.num_lost = 0;
          s.next_txack_index = 0;
          s.usec_per_pkt = ntohl(s.rx.usec_per_pkt);
          memset(&s.tx, 0, sizeof(s.tx));
        }
      }

      handle_packet(&s, now);
    }
  }

  // TODO(pmccurdy): Separate out per-client and global stats.
  printf("\n---\n");
  printf("tx: min/avg/max/mdev = %.2f/%.2f/%.2f/%.2f ms\n",
         s.lat_tx_min / 1000.0,
         DIV(s.lat_tx_sum, s.lat_tx_count) / 1000.0,
         s.lat_tx_max / 1000.0,
         onepass_stddev(
             s.lat_tx_var_sum, s.lat_tx_sum, s.lat_tx_count) / 1000.0);
  printf("rx: min/avg/max/mdev = %.2f/%.2f/%.2f/%.2f ms\n",
         s.lat_rx_min / 1000.0,
         DIV(s.lat_rx_sum, s.lat_rx_count) / 1000.0,
         s.lat_rx_max / 1000.0,
         onepass_stddev(
             s.lat_rx_var_sum, s.lat_rx_sum, s.lat_rx_count) / 1000.0);
  printf("\n");

  if (ai) freeaddrinfo(ai);
  if (sock >= 0) close(sock);
  return 0;
}
