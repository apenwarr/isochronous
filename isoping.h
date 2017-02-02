/*
 * Copyright 2016 Google Inc. All rights reserved.
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
#ifndef ISOPING_H
#define ISOPING_H

#include <map>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <queue>
#include <random>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

// Number of bytes required to store the cookie, which is a SHA-256 hash.
#define COOKIE_SIZE 32
// Number of bytes used to store the random cookie secret.
#define COOKIE_SECRET_SIZE 16

enum {
  PACKET_TYPE_ACK = 0,
  PACKET_TYPE_HANDSHAKE,
};

// Layout of the UDP packets exchanged between client and server.
// All integers are in network byte order.
// Packets have exactly the same structure in both directions.
struct Packet {
  uint32_t magic;     // magic number to reject bogus packets
  uint32_t id;        // sequential packet id number
  uint32_t txtime;    // transmitter's monotonic time when pkt was sent
  uint32_t clockdiff; // estimate of (transmitter's clk) - (receiver's clk)
  uint32_t usec_per_pkt; // microseconds of delay between packets
  uint32_t num_lost;  // number of pkts transmitter expected to get but didn't
  uint8_t packet_type; // 0 for acks, 1 for handshake packet
  uint8_t first_ack;  // starting index in acks[] circular buffer
  union {
    // Data used for handshake packets.
    struct {
      uint32_t version; // max version of the isoping protocol supported
      uint32_t cookie_epoch; // which cookie we're using
      unsigned char cookie[COOKIE_SIZE]; // actual cookie value
    } handshake;
    // Data used for ack packets.
    struct {
      // txtime==0 for empty elements in this array.
      uint32_t id;      // id field from a received packet
      uint32_t rxtime;  // receiver's monotonic time when pkt arrived
    } acks[64];
  } data;
};


// Data we track per session.
struct Session {
  Session(uint32_t first_send, uint32_t usec_per_pkt,
          const struct sockaddr_storage &remoteaddr, size_t remoteaddr_len);
  int32_t usec_per_pkt;
  int32_t usec_per_print;

  // The peer's address.
  struct sockaddr_storage remoteaddr;
  socklen_t remoteaddr_len;

  enum {
    NEW_SESSION = 0,     // No packets exchanged yet.
    HANDSHAKE_REQUESTED, // Client has sent initial packet to server, i.e. SYN.
    COOKIE_GENERATED,    // Server has replied with cookie, i.e. SYN|ACK.
    ESTABLISHED          // Client has echoed cookie back, i.e. ACK.
  } handshake_state;
  int handshake_retry_count;
  static const int handshake_timeout_usec = 1000000;

  // WARNING: lots of math below relies on well-defined uint32/int32
  // arithmetic overflow behaviour, plus the fact that when we subtract
  // two successive timestamps (for example) they will be less than 2^31
  // microseconds apart.  It would be safer to just use 64-bit values
  // everywhere, but that would cut the number of acks-per-packet in half,
  // which would be unfortunate.
  uint32_t next_tx_id;       // id field for next transmit
  uint32_t next_rx_id;       // expected id field for next receive
  uint32_t next_rxack_id;    // expected ack.id field in next received ack
  uint32_t start_rtxtime;    // remote's txtime at startup
  uint32_t start_rxtime;     // local rxtime at startup
  uint32_t last_rxtime;      // local rxtime of last received packet
  int32_t min_cycle_rxdiff;  // smallest packet delay seen this cycle
  uint32_t next_cycle;       // time when next cycle begins
  uint32_t next_send;        // time when we'll send next pkt
  uint32_t num_lost;         // number of rx packets not received
  int next_txack_index;      // next array item to fill in tx.acks
  struct Packet tx, rx;      // transmit and received packet buffers
  char last_ackinfo[128];    // human readable format of latest ack
  uint32_t last_print;       // time of last packet printout
  // Packet statistics counters for transmit and receive directions.
  long long lat_tx, lat_tx_min, lat_tx_max,
      lat_tx_count, lat_tx_sum, lat_tx_var_sum;
  long long lat_rx, lat_rx_min, lat_rx_max,
      lat_rx_count, lat_rx_sum, lat_rx_var_sum;
};

// Comparator for use with sockaddr_in and sockaddr_in6 values.  Sorts by
// address family first, then on the IPv4/6 address, then the port number.
struct CompareSockaddr {
  bool operator()(const struct sockaddr_storage &lhs,
                  const struct sockaddr_storage &rhs);
};

typedef std::map<struct sockaddr_storage, Session, CompareSockaddr>
    SessionMap;

// Compares the next_send values of each referenced Session, sorting the earlier
// timestamps first.
struct CompareNextSend {
  bool operator()(const SessionMap::iterator &lhs,
                  const SessionMap::iterator &rhs);
};

struct Sessions {
 public:
  Sessions()
      : md(EVP_sha256()),
        rng(std::random_device()()),
        cookie_epoch(0) {
    NewRandomCookieSecret();
    EVP_MD_CTX_init(&digest_context);
  }

  ~Sessions() {
    EVP_MD_CTX_cleanup(&digest_context);
  }

  // Rotates the cookie secrets if they haven't been changed in a while.
  void MaybeRotateCookieSecrets();

  // Rotate the cookie secrets using the given epoch directly.  Only for use in
  // unit tests.
  void RotateCookieSecrets(uint32_t new_epoch);

  // Calculates a handshake cookie based on the provided client IP address and
  // the relevant parameters in p, using the current cookie secret, and places
  // the result in p.
  bool CalculateCookie(Packet *p, struct sockaddr_storage *remoteaddr,
                       size_t remoteaddr_len);

  // Returns true if the packet contains a handshake packet with a valid cookie.
  bool ValidateCookie(Packet *p, struct sockaddr_storage *addr,
                      socklen_t addr_len);

  SessionMap::iterator NewSession(uint32_t first_send,
                                  uint32_t usec_per_pkt,
                                  struct sockaddr_storage *addr,
                                  socklen_t addr_len);

  uint32_t next_send_time() {
    if (next_sends.size() == 0) {
      return 0;
    }
    return next_sends.top()->second.next_send;
  }

  // All active sessions, indexed by remote address/port.
  SessionMap session_map;
  // A queue of upcoming send times, ordered most recent first, referencing
  // entries in the session map.
  std::priority_queue<SessionMap::iterator, std::vector<SessionMap::iterator>,
      CompareNextSend> next_sends;

 private:
  void NewRandomCookieSecret();
  bool CalculateCookieWithSecret(Packet *p, struct sockaddr_storage *remoteaddr,
                                 size_t remoteaddr_len, unsigned char *secret,
                                 size_t secret_len);

  // Fields required for calculating and verifying cookies.
  EVP_MD_CTX digest_context;
  const EVP_MD *md;
  std::mt19937_64 rng;
  uint32_t cookie_epoch;
  unsigned char cookie_secret[COOKIE_SECRET_SIZE];
  uint32_t prev_cookie_epoch;
  unsigned char prev_cookie_secret[COOKIE_SECRET_SIZE];
};

// Process an incoming packet from the socket.
void handle_packet(struct Sessions *s, struct Session *session, Packet *rx,
                   int sock, struct sockaddr_storage *rxaddr,
                   socklen_t rxaddr_len, uint32_t now, int is_server);

// Process an established Session's incoming ack packet, from s->rx.
void handle_ack_packet(struct Session *s, uint32_t now);

// Server-only: processes a handshake packet from a new client in rx. Replies
// with a cookie if no cookie provided, or validates the provided cookie and
// establishes a new Session.
void handle_new_client_handshake_packet(Sessions *s, Packet *rx, int sock,
                                       struct sockaddr_storage *remoteaddr,
                                       size_t remoteaddr_len, uint32_t now);

// Client-only: processes a handshake packet received from the server.
// Configures the Session to echo the provided cookie back to the server.
void handle_server_handshake_packet(Sessions *s, Packet *rx, uint32_t now);

// Sets all the elements of s->tx to be ready to be sent to the other side.
void prepare_tx_packet(struct Session *s);

// Sends a packet to all waiting sessions where the appropriate amount of time
// has passed.
int send_waiting_packets(Sessions *s, int sock, uint32_t now, int is_server);

// Sends a packet from the given session to the given socket immediately.
int send_packet(struct Session *s, int sock, int is_server);

// Reads a packet from sock and stores it in s->rx.  Assumes a packet is
// currently readable.
int read_incoming_packet(Sessions *s, int sock, uint32_t now, int is_server);

// Sets the global packets_per_sec value.  Used for test purposes only.
void set_packets_per_sec(double new_pps);

// Parses arguments and runs the main loop.  Distinct from main() for unit test
// purposes.
int isoping_main(int argc, char **argv);

#endif
