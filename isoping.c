/*
 * Like ping, but sends packets isochronously (equally spaced in time) in
 * each direction.  By being clever, we can use the known timing of each
 * packet to determine, on a noisy network, which direction is dropping or
 * delaying packets and by how much.
 *
 * Also unlike ping, this requires a server (ie. another copy of this
 * program) to be running on the remote end.
 */
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

#define MAGIC 0x424c4950
#define SERVER_PORT 4948
#define USEC_PER_PKT (100*1000)

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


// Layout of the UDP packets exchanged between client and server.
// All integers are in network byte order.
// Packets have exactly the same structure in both directions.
struct Packet {
  uint32_t magic;     // magic number to reject bogus packets
  uint32_t id;        // sequential packet id number
  uint32_t txtime;    // transmitter's monotonic time when pkt was sent
  uint32_t clockdiff; // estimate of (transmitter's clk) - (receiver's clk)
  uint32_t num_lost;  // number of pkts transmitter expected to get but didn't
  uint32_t first_ack; // starting index in acks[] circular buffer
  struct {
    // txtime==0 for empty elements in this array.
    uint32_t id;      // id field from a received packet
    uint32_t rxtime;  // receiver's monotonic time when pkt arrived
  } acks[64];
};


int want_to_die;


void sighandler(int sig) {
  want_to_die = 1;
}


// Returns the kernel monotonic timestamp in microseconds, truncated to
// 32 bits.  That will wrap around every ~4000 seconds, which is okay
// for our purposes.  We use 32 bits to save space in our packets.
// This function never returns the value 0; it returns 1 instead, so that
// 0 can be used as a magic value.
#ifdef __MACH__  // MacOS X doesn't have clock_gettime()
#include <mach/mach.h>
#include <mach/mach_time.h>

static uint32_t ustime(void) {
  static mach_timebase_info_data_t timebase;
  if (!timebase.denom) mach_timebase_info(&timebase);
  uint32_t result = (mach_absolute_time() * timebase.numer /
                     timebase.denom / 1000);
  return !result ? 1 : result;
}
#else
static uint32_t ustime(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
    perror("clock_gettime");
    exit(98); // really should never happen, so don't try to recover
  }
  uint32_t result = ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
  return !result ? 1 : result;
}
#endif


void usage_and_die(char *argv0) {
  fprintf(stderr,
          "\n"
          "Usage: %s                          (server mode)\n"
          "   or: %s <server-hostname-or-ip>  (client mode)\n",
          argv0, argv0);
  exit(99);
}


// Render the given sockaddr as a string.  (Uses a static internal buffer
// which is overwritten each time.)
const char *sockaddr_to_str(struct sockaddr *sa) {
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


int main(int argc, char **argv) {
  int is_server = 1;
  struct sockaddr_in6 listenaddr, rxaddr, last_rxaddr;
  struct sockaddr *remoteaddr = NULL;
  socklen_t remoteaddr_len = 0, rxaddr_len = 0;
  struct addrinfo *ai = NULL;
  int sock = -1;

  sock = socket(PF_INET6, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("socket");
    return 1;
  }

  if (argc <= 1) {
    is_server = 1;
    sock = socket(PF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
      perror("socket");
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
    fprintf(stderr, "server listening at [%s]:%d\n",
           sockaddr_to_str((struct sockaddr *)&listenaddr),
           ntohs(listenaddr.sin6_port));
  } else if (argc <= 2) {
    is_server = 0;
    struct addrinfo hints = {
      ai_flags: AI_ADDRCONFIG | AI_V4MAPPED,
      ai_family: AF_INET6,
      ai_socktype: SOCK_DGRAM,
    };
    int err = getaddrinfo(argv[1], STR(SERVER_PORT), &hints, &ai);
    if (err != 0 || !ai) {
      fprintf(stderr, "getaddrinfo(%s): %s\n", argv[1], gai_strerror(err));
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

  // WARNING: lots of math below relies on well-defined uint32/int32
  // arithmetic overflow behaviour, plus the fact that when we subtract
  // two successive timestamps (for example) they will be less than 2^31
  // microseconds apart.  It would be safer to just use 64-bit values
  // everywhere, but that would cut the number of acks-per-packet in half,
  // which would be unfortunate.
  uint32_t next_tx_id = 1;       // id field for next transmit
  uint32_t next_rx_id = 0;       // expected id field for next receive
  uint32_t next_rxack_id = 0;    // expected ack.id field in next received ack
  uint32_t start_rtxtime = 0;    // remote's txtime at startup
  uint32_t start_rxtime = 0;     // local rxtime at startup
  uint32_t last_rxtime = 0;      // local rxtime of last received packet
  int32_t min_cycle_rxdiff = 0;  // smallest packet delay seen this cycle
  uint32_t next_cycle = 0;       // time when next cycle begins
  uint32_t now = ustime();       // current time
  uint32_t next_send = now + USEC_PER_PKT;  // time when we'll send next pkt
  uint32_t num_lost = 0;         // number of rx packets not received
  int next_txack_index = 0;      // next array item to fill in tx.acks
  struct Packet tx, rx;          // transmit and received packet buffers
  char last_ackinfo[128] = "";   // human readable format of latest ack
  // Packet count, total time, and total variance (sum of squares of diff
  // from the mean) for all packets sent and received, respectively.
  long long lat_tx_count = 0, lat_tx_sum = 0, lat_tx_var_sum = 0;
  long long lat_rx_count = 0, lat_rx_sum = 0, lat_rx_var_sum = 0;

  memset(&tx, 0, sizeof(tx));
  signal(SIGINT, sighandler);

  while (!want_to_die) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    struct timeval tv;
    tv.tv_sec = 0;

    if (DIFF(next_send, now) < 0) {
      tv.tv_usec = 0;
    } else {
      tv.tv_usec = DIFF(next_send, now);
    }
    int nfds = select(sock + 1, &rfds, NULL, NULL, remoteaddr ? &tv : NULL);
    now = ustime();
    if (nfds < 0 && errno != EINTR) {
      perror("select");
      return 1;
    }

    // time to send the next packet?
    if (remoteaddr && DIFF(now, next_send) >= 0) {
      tx.magic = htonl(MAGIC);
      tx.id = htonl(next_tx_id++);
      tx.txtime = htonl(next_send);
      tx.clockdiff = htonl(start_rxtime - start_rtxtime);
      tx.num_lost = htonl(num_lost);
      tx.first_ack = htonl(next_txack_index);
      // note: tx.acks[] is filled in incrementally; we just transmit the
      // current state of it here.  The reason we keep a list of the most
      // recent acks is in case our packet gets lost, so the receiver will
      // have more chances to receive the timing information for the packets
      // it sent us.
      if (is_server) {
        if (sendto(sock, &tx, sizeof(tx), 0,
                   remoteaddr, remoteaddr_len) < 0) {
          perror("sendto");
        }
      } else {
        if (send(sock, &tx, sizeof(tx), 0) < 0) {
          perror("send");
        }
      }

      if (is_server && DIFF(now, last_rxtime) > 60*1000*1000) {
        fprintf(stderr, "client disconnected.\n");
        remoteaddr = NULL;
      }
      next_send += USEC_PER_PKT;
    }

    if (nfds > 0) {
      // incoming packet
      rxaddr_len = sizeof(rxaddr);
      ssize_t got = recvfrom(sock, &rx, sizeof(rx), 0,
                             (struct sockaddr *)&rxaddr, &rxaddr_len);
      if (got < 0) {
        perror("recvfrom");
        continue;
      }
      if (got != sizeof(rx) || rx.magic != htonl(MAGIC)) {
        fprintf(stderr, "got invalid packet of length %ld\n", (long)got);
        continue;
      }

      // is it a new client?
      if (is_server) {
        // TODO(apenwarr): fork() for each newly connected client.
        //  The way the code is right now, it won't work right at all
        //  if there are two clients sending us packets at once.
        //  That's okay for a first round of controlled tests.
        if (!remoteaddr ||
            memcmp(&rxaddr, &last_rxaddr, sizeof(rxaddr)) != 0) {
          fprintf(stderr, "new client connected: %s\n",
                  sockaddr_to_str((struct sockaddr *)&rxaddr));
          memcpy(&last_rxaddr, &rxaddr, sizeof(rxaddr));
          remoteaddr = (struct sockaddr *)&last_rxaddr;
          remoteaddr_len = rxaddr_len;

          next_send = now + 10*1000;
          next_tx_id = 1;
          next_rx_id = next_rxack_id = 0;
          start_rtxtime = start_rxtime = 0;
          num_lost = 0;
          next_txack_index = 0;
          memset(&tx, 0, sizeof(tx));
        }
      }

      // process the incoming packet header.
      // Most of the complexity here comes from the fact that the remote
      // system's clock will be skewed vs. ours.  (We use CLOCK_MONOTONIC
      // instead of CLOCK_REALTIME, so unless we figure out the skew offset,
      // it's essentially meaningless to compare the two values.)  We can
      // however assume that block clocks are ticking at 1 microsecond per
      // tick... except for inevitable clock rate errors, which we have to
      // account for occasionally.

      uint32_t txtime = ntohl(rx.txtime), rxtime = now;
      uint32_t id = ntohl(rx.id);
      if (!next_rx_id) {
        // The remote txtime is told to us by the sender, so it is always
        // perfectly correct... but it uses the sender's clock.
        start_rtxtime = txtime - id * USEC_PER_PKT;

        // The receive time uses our own clock and is estimated by us, so
        // it needs to be corrected over time because:
        //   a) the two clocks inevitably run at slightly different speeds;
        //   b) there's an unknown, variable, network delay between tx and rx.
        // Here, we're just assigning an initial estimate.
        start_rxtime = rxtime - id * USEC_PER_PKT;

        min_cycle_rxdiff = 0;
        next_rx_id = id;
        next_cycle = now + USEC_PER_CYCLE;
      }

      // see if we missed receiving any previous packets.
      int32_t tmpdiff = DIFF(id, next_rx_id);
      if (tmpdiff > 0) {
        // arriving packet has id > expected, so something was lost.
        // Note that we don't use the rx.acks[] structure to determine packet
        // loss; that's because the limited size of the array means that,
        // during a longer outage, we might not see an ack for a packet
        // *even if that packet arrived safely* at the remote.  So we count
        // on the remote end to count its own packet losses using sequence
        // numbers, and send that count back to us.  We do the same here
        // for incoming packets from the remote, and send the error count
        // back to them next time we're ready to transmit.
        fprintf(stderr, "lost %ld  expected=%ld  got=%ld\n",
                (long)tmpdiff, (long)next_rx_id, (long)id);
        num_lost += tmpdiff;
        next_rx_id += tmpdiff + 1;
      } else if (!tmpdiff) {
        // exactly as expected; good.
        next_rx_id++;
      } else if (tmpdiff < 0) {
        // packet before the expected one? weird.
        fprintf(stderr, "out-of-order packets? %ld\n", (long)tmpdiff);
      }

      // fix up the clock offset if there's any drift.
      tmpdiff = DIFF(rxtime, start_rxtime + id * USEC_PER_PKT);
      if (tmpdiff < 0) {
        // packet arrived before predicted time, so prediction was based on
        // a packet that was "slow" before, or else one of our clocks is
        // drifting. Use earliest legitimate start time.
        fprintf(stderr, "time paradox: backsliding start by %ld usec\n",
                (long)tmpdiff);
        start_rxtime = rxtime - id * USEC_PER_PKT;
      }
      int32_t rxdiff = DIFF(rxtime, start_rxtime + id * USEC_PER_PKT);

      // Figure out the offset between our clock and the remote's clock, so
      // we can calculate the minimum round trip time (rtt). Then, because
      // the consecutive packets sent in both directions are equally spaced
      // in time, we can figure out how much a particular packet was delayed
      // in transit - independently in each direction! This is an advantage
      // over the normal "ping" program which has no way to tell which
      // direction caused the delay, or which direction dropped the packet.

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
      // ...but that last subtraction is dangerous because if we divide by
      // 2 to get offset, it doesn't work with 32-bit math, which may have
      // discarded a high-order bit somewhere along the way.  Instead,
      // we can extract offset once we have rtt by substituting it into
      //   clockdiff = offset + 1/2 rtt
      //   offset = clockdiff - 1/2 rtt
      // (Dividing rtt by 2 is safe since it's always small and positive.)
      //
      // (This example assumes 1/2 rtt in each direction. There's no way to
      // determine it more accurately than that.)
      int32_t clockdiff = DIFF(start_rxtime, start_rtxtime);
      int32_t rtt = clockdiff + ntohl(rx.clockdiff);
      int32_t offset = DIFF(clockdiff, -rtt / 2);
      lat_rx_count++;
      lat_rx_sum += rxdiff + rtt/2;
      long long lat_rx_var = rxdiff + rtt/2 - DIV(lat_rx_sum, lat_rx_count);
      lat_rx_var_sum += lat_rx_var * lat_rx_var;
      printf("%16s  %6.1f ms rx  (min=%.1f)  loss: %ld/%ld tx  %ld/%ld rx\n",
             last_ackinfo,
             (rxdiff + rtt/2) / 1000.0, (rtt/2) / 1000.0,
             (long)ntohl(rx.num_lost), (long)next_tx_id - 1,
             (long)num_lost, (long)next_rx_id - 1);
      last_ackinfo[0] = '\0';
      if (rxdiff < min_cycle_rxdiff) min_cycle_rxdiff = rxdiff;
      if (DIFF(now, next_cycle) >= 0) {
        if (min_cycle_rxdiff > 0) {
          fprintf(stderr, "clock skew: sliding start by %ld usec\n",
                  (long)min_cycle_rxdiff);
          start_rxtime += min_cycle_rxdiff;
        }
        min_cycle_rxdiff = 0x7fffffff;
        next_cycle += USEC_PER_CYCLE;
      }

      // schedule this for an ack next time we send the packet
      tx.acks[next_txack_index].id = htonl(id);
      tx.acks[next_txack_index].rxtime = htonl(rxtime);
      next_txack_index = (next_txack_index + 1) % ARRAY_LEN(tx.acks);

      // see which of our own transmitted packets have been acked
      uint32_t first_ack = ntohl(rx.first_ack);
      for (uint32_t i = 0; i < ARRAY_LEN(rx.acks); i++) {
        uint32_t acki = (first_ack + i) % ARRAY_LEN(rx.acks);
        uint32_t ackid = ntohl(rx.acks[acki].id);
        if (!ackid) continue;  // empty slot
        if (DIFF(ackid, next_rxack_id) >= 0) {
          // an expected ack
          uint32_t start_txtime = next_send - next_tx_id * USEC_PER_PKT;
          uint32_t rrxtime = ntohl(rx.acks[acki].rxtime);
          // note: already contains 1/2 rtt, unlike rxdiff
          int32_t txdiff = DIFF(rrxtime + offset,
                                start_txtime + ackid * USEC_PER_PKT);
          if (last_ackinfo[0]) {
            printf("%16s\n", last_ackinfo);
          }
          snprintf(last_ackinfo, sizeof(last_ackinfo), "%6.1f ms tx",
                   txdiff / 1000.0);
          next_rxack_id = ackid + 1;
          lat_tx_sum += txdiff;
          lat_tx_count++;
          long long lat_tx_var = txdiff - DIV(lat_tx_sum, lat_tx_count);
          lat_tx_var_sum += lat_tx_var * lat_tx_var;
        }
      }

      last_rxtime = rxtime;
    }
  }

  printf("\nStats: "
         "tx: %.2f ms avg, %.2f stddev   "
         "rx: %.2f ms avg, %.2f stddev\n",
         DIV(lat_tx_sum, lat_tx_count) / 1000.0,
         sqrt(DIV(lat_tx_var_sum, lat_tx_count)) / 1000.0,
         DIV(lat_rx_sum, lat_rx_count) / 1000.0,
         sqrt(DIV(lat_rx_var_sum, lat_rx_count)) / 1000.0);

  if (ai) freeaddrinfo(ai);
  if (sock >= 0) close(sock);
  return 0;
}
