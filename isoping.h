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

#include <stdint.h>
#include <sys/socket.h>

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
  uint32_t first_ack; // starting index in acks[] circular buffer
  struct {
    // txtime==0 for empty elements in this array.
    uint32_t id;      // id field from a received packet
    uint32_t rxtime;  // receiver's monotonic time when pkt arrived
  } acks[64];
};


// Data we track per session.
struct Session {
  Session(uint32_t now);
  int32_t usec_per_pkt;
  int32_t usec_per_print;

  // The peer's address.
  struct sockaddr *remoteaddr;
  socklen_t remoteaddr_len;

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

// Process the Session's incoming packet, from s->rx.
void handle_packet(struct Session *s, uint32_t now);

// Sets all the elements of s->tx to be ready to be sent to the other side.
void prepare_tx_packet(struct Session *s);

// Sends a packet to the socket if the appropriate amount of time has passed.
int maybe_send_packet(struct Session *s, int sock, uint32_t now);

// Reads a packet from sock and stores it in s->rx.  Assumes a packet is
// currently readable.
int read_incoming_packet(struct Session *s, int sock, uint32_t now);

// Parses arguments and runs the main loop.  Distinct from main() for unit test
// purposes.
int isoping_main(int argc, char **argv);

#endif
