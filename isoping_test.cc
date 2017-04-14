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

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <memory.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <wvtest.h>

#include "isoping.h"

uint32_t send_next_ack_packet(Session *from, uint32_t from_base,
                          Session *to, uint32_t to_base, uint32_t latency) {
  uint32_t t = from->next_send - from_base;
  prepare_tx_packet(from);
  to->rx = from->tx;
  from->next_send += from->usec_per_pkt;
  t += latency;
  handle_ack_packet(to, to_base + t);
  fprintf(stderr,
          "**Sent packet: txtime=%d, start_txtime=%d, rxtime=%d, "
          "start_rxtime=%d, latency=%d, t_from=%d, t_to=%d\n",
          from->next_send,
          to->start_rtxtime,
          to_base + t,
          to->start_rxtime,
          latency,
          t - latency,
          t);

  return t;
}

WVTEST_MAIN("isoping algorithm logic") {
  // Establish a positive base time for client and server.  This is conceptually
  // the instant when the client sends its first message to the server, as
  // measured by the clocks on each side (note: this is before the server
  // receives the message).
  uint32_t cbase = 400 * 1000;
  uint32_t sbase = 600 * 1000;
  uint32_t real_clockdiff = sbase - cbase;
  uint32_t usec_per_pkt = 100 * 1000;

  // The states of the client and server.
  struct sockaddr_storage empty_sockaddr;
  struct Session c(cbase, usec_per_pkt, empty_sockaddr, sizeof(empty_sockaddr));
  struct Session s(sbase, usec_per_pkt, empty_sockaddr, sizeof(empty_sockaddr));
  c.handshake_state = Session::ESTABLISHED;
  s.handshake_state = Session::ESTABLISHED;

  // One-way latencies: cs_latency is the latency from client to server;
  // sc_latency is from server to client.
  uint32_t cs_latency = 24 * 1000;
  uint32_t sc_latency = 25 * 1000;
  uint32_t half_rtt = (sc_latency + cs_latency) / 2;

  // Elapsed time, relative to the base time for each clock.
  uint32_t t = 0;

  // Send the initial packet from client to server.  This isn't enough to let us
  // draw any useful latency conclusions.
  t = send_next_ack_packet(&c, cbase, &s, sbase, cs_latency);
  uint32_t rxtime = sbase + t;
  s.next_send = rxtime + 10 * 1000;

  printf("last_rxtime: %d\n", s.last_rxtime);
  printf("min_cycle_rxdiff: %d\n", s.min_cycle_rxdiff);
  WVPASSEQ(s.rx.clockdiff, 0);
  WVPASSEQ(s.last_rxtime, rxtime);
  WVPASSEQ(s.min_cycle_rxdiff, 0);
  WVPASSEQ(ntohl(s.tx.data.acks[0].id), 1);
  WVPASSEQ(s.next_txack_index, 1);
  WVPASSEQ(ntohl(s.tx.data.acks[s.tx.first_ack].id), 1);
  WVPASSEQ(ntohl(s.tx.data.acks[s.tx.first_ack].rxtime), rxtime);
  WVPASSEQ(s.start_rxtime, rxtime - c.usec_per_pkt);
  WVPASSEQ(s.start_rtxtime, cbase - c.usec_per_pkt);
  WVPASSEQ(s.next_send, rxtime + 10 * 1000);

  // Reply to the client.
  t = send_next_ack_packet(&s, sbase, &c, cbase, sc_latency);

  // Now we have enough data to figure out latencies on the client.
  rxtime = cbase + t;
  WVPASSEQ(c.start_rxtime, rxtime - s.usec_per_pkt);
  WVPASSEQ(c.start_rtxtime, sbase + cs_latency + 10 * 1000 - s.usec_per_pkt);
  WVPASSEQ(c.min_cycle_rxdiff, 0);
  WVPASSEQ(ntohl(c.rx.clockdiff), sbase - cbase + cs_latency);
  WVPASSEQ(ntohl(c.tx.data.acks[c.tx.first_ack].id), 1);
  WVPASSEQ(ntohl(c.tx.data.acks[c.tx.first_ack].rxtime), rxtime);
  WVPASSEQ(c.num_lost, 0);
  WVPASSEQ(c.lat_tx_count, 1);
  WVPASSEQ(c.lat_tx, half_rtt);
  WVPASSEQ(c.lat_rx_count, 1);
  WVPASSEQ(c.lat_rx, half_rtt);
  WVPASSEQ(c.num_lost, 0);

  // Round 2
  t = send_next_ack_packet(&c, cbase, &s, sbase, cs_latency);
  rxtime = sbase + t;

  // Now the server also knows latencies.
  WVPASSEQ(s.start_rxtime, sbase + cs_latency - s.usec_per_pkt);
  WVPASSEQ(s.start_rtxtime, cbase - c.usec_per_pkt);
  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency);
  WVPASSEQ(ntohl(s.tx.data.acks[s.tx.first_ack].id), 2);
  WVPASSEQ(ntohl(s.tx.data.acks[s.tx.first_ack].rxtime), rxtime);
  WVPASSEQ(s.num_lost, 0);
  WVPASSEQ(s.lat_tx_count, 1);
  WVPASSEQ(s.lat_tx, half_rtt);
  WVPASSEQ(s.lat_rx_count, 1);
  WVPASSEQ(s.lat_rx, half_rtt);
  WVPASSEQ(s.num_lost, 0);

  // Increase the latencies in both directions, reply to client.
  int32_t latency_diff = 10 * 1000;
  t = send_next_ack_packet(&s, sbase, &c, cbase, sc_latency + latency_diff);

  rxtime = cbase + t;
  WVPASSEQ(ntohl(s.tx.clockdiff), real_clockdiff + cs_latency);
  WVPASSEQ(c.start_rxtime,
           rxtime - ntohl(s.tx.id) * s.usec_per_pkt - latency_diff);
  WVPASSEQ(c.start_rtxtime, sbase + cs_latency + 10 * 1000 - s.usec_per_pkt);
  WVPASSEQ(ntohl(c.tx.data.acks[c.tx.first_ack].id), 2);
  WVPASSEQ(ntohl(c.tx.data.acks[c.tx.first_ack].rxtime), rxtime);
  WVPASSEQ(c.num_lost, 0);
  WVPASSEQ(c.lat_tx_count, 2);
  WVPASSEQ(c.lat_tx, half_rtt);
  WVPASSEQ(c.lat_rx_count, 2);
  WVPASSEQ(c.lat_rx, half_rtt + latency_diff);
  WVPASSEQ(c.num_lost, 0);

  // Client replies with increased latency, server notices.
  t = send_next_ack_packet(&c, cbase, &s, sbase, cs_latency + latency_diff);

  rxtime = sbase + t;
  WVPASSEQ(ntohl(c.tx.clockdiff), - real_clockdiff + sc_latency);
  WVPASSEQ(s.start_rxtime, sbase + cs_latency - s.usec_per_pkt);
  WVPASSEQ(s.start_rtxtime, cbase - c.usec_per_pkt);
  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency);
  WVPASSEQ(ntohl(s.tx.data.acks[s.tx.first_ack].id), 3);
  WVPASSEQ(ntohl(s.tx.data.acks[s.tx.first_ack].rxtime), rxtime);
  WVPASSEQ(s.num_lost, 0);
  WVPASSEQ(s.lat_tx_count, 2);
  WVPASSEQ(s.lat_tx, half_rtt + latency_diff);
  WVPASSEQ(s.lat_rx_count, 2);
  WVPASSEQ(s.lat_rx, half_rtt + latency_diff);
  WVPASSEQ(s.num_lost, 0);

  // Lose a server->client packet, send the next client->server packet, verify
  // only the received packets were acked.
  s.next_send += s.usec_per_pkt;
  s.next_tx_id++;

  t = send_next_ack_packet(&c, cbase, &s, sbase, cs_latency + latency_diff);

  rxtime = sbase + t;
  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency);
  WVPASSEQ(ntohl(s.tx.data.acks[s.tx.first_ack].id), 3);
  WVPASSEQ(ntohl(s.tx.data.acks[s.tx.first_ack].rxtime),
           rxtime - s.usec_per_pkt);
  WVPASSEQ(s.num_lost, 0);
  WVPASSEQ(s.lat_tx_count, 2);
  WVPASSEQ(s.lat_tx, half_rtt + latency_diff);
  WVPASSEQ(s.lat_rx_count, 3);
  WVPASSEQ(s.lat_rx, half_rtt + latency_diff);
  WVPASSEQ(s.num_lost, 0);

  // Remove the extra latency from server->client, send the next packet, have
  // the client receive it and notice the lost packet and reduced latency.
  t = send_next_ack_packet(&s, sbase, &c, cbase, sc_latency);

  rxtime = cbase + t;
  WVPASSEQ(ntohl(c.tx.data.acks[c.tx.first_ack].id), 4);
  WVPASSEQ(ntohl(c.tx.data.acks[c.tx.first_ack].rxtime), rxtime);
  WVPASSEQ(c.num_lost, 1);
  WVPASSEQ(c.lat_tx_count, 4);
  WVPASSEQ(c.lat_tx, half_rtt + latency_diff);
  WVPASSEQ(c.lat_rx_count, 3);
  WVPASSEQ(c.lat_rx, half_rtt);
  WVPASSEQ(c.num_lost, 1);

  // A tiny reduction in latency shows up in min_cycle_rxdiff.
  latency_diff = 0;
  int32_t latency_mini_diff = -15;
  t = send_next_ack_packet(&c, cbase, &s, sbase,
                           cs_latency + latency_mini_diff);

  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency);
  WVPASSEQ(s.min_cycle_rxdiff, latency_mini_diff);
  WVPASSEQ(s.start_rxtime, sbase + cs_latency - s.usec_per_pkt);
  WVPASSEQ(s.lat_tx, half_rtt);
  WVPASSEQ(s.lat_rx, half_rtt + latency_mini_diff);

  t = send_next_ack_packet(&s, sbase, &c, cbase,
                           sc_latency + latency_mini_diff);

  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency);
  WVPASSEQ(c.min_cycle_rxdiff, latency_mini_diff);
  WVPASSEQ(c.lat_tx, half_rtt + latency_mini_diff);
  WVPASSEQ(c.lat_rx, half_rtt + latency_mini_diff);

  // Reduce the latency dramatically, verify that both sides see it, and the
  // start time is modified (not the min_cycle_rxdiff).
  latency_diff = -22 * 1000;
  t = send_next_ack_packet(&c, cbase, &s, sbase, cs_latency + latency_diff);

  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency);
  WVPASSEQ(s.min_cycle_rxdiff, latency_mini_diff);
  // We see half the latency diff applied to each side of the connection because
  // the reduction in latency creates a time paradox, rebasing the start time
  // and recalculating the RTT.
  WVPASSEQ(s.start_rxtime, sbase + cs_latency + latency_diff - s.usec_per_pkt);
  WVPASSEQ(s.lat_tx, half_rtt + latency_diff/2 + latency_mini_diff);
  WVPASSEQ(s.lat_rx, half_rtt + latency_diff/2);

  t = send_next_ack_packet(&s, sbase, &c, cbase, sc_latency + latency_diff);

  // Now we see the new latency applied to both sides.
  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency);
  WVPASSEQ(c.min_cycle_rxdiff, latency_mini_diff);
  WVPASSEQ(c.lat_tx, half_rtt + latency_diff);
  WVPASSEQ(c.lat_rx, half_rtt + latency_diff);

  // Restore latency on one side of the connection, verify that we track it on
  // only one side and we've improved our clock sync.
  t = send_next_ack_packet(&c, cbase, &s, sbase, cs_latency);

  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency + latency_diff);
  WVPASSEQ(s.lat_tx, half_rtt + latency_diff);
  WVPASSEQ(s.lat_rx, half_rtt);

  // And double-check that the other side also sees the improved clock sync and
  // one-sided latency on the correct side.
  t = send_next_ack_packet(&s, sbase, &c, cbase, sc_latency + latency_diff);

  WVPASSEQ(ntohl(c.rx.clockdiff), sbase - cbase + cs_latency + latency_diff);
  WVPASSEQ(c.lat_tx, half_rtt);
  WVPASSEQ(c.lat_rx, half_rtt + latency_diff);
}

// Verify that isoping handles clocks ticking at different rates.
WVTEST_MAIN("isoping clock drift") {
  uint32_t cbase = 1400 * 1000;
  uint32_t sbase = 1600 * 1000;
  uint32_t usec_per_pkt = 100 * 1000;

  // The states of the client and server.
  struct sockaddr_storage empty_sockaddr;
  struct Session c(cbase, usec_per_pkt, empty_sockaddr, sizeof(empty_sockaddr));
  struct Session s(sbase, usec_per_pkt, empty_sockaddr, sizeof(empty_sockaddr));
  c.handshake_state = Session::ESTABLISHED;
  s.handshake_state = Session::ESTABLISHED;
  // Send packets infrequently, to get new cycles more often.
  s.usec_per_pkt = 1 * 1000 * 1000;
  c.usec_per_pkt = 1 * 1000 * 1000;

  // One-way latencies: cs_latency is the latency from client to server;
  // sc_latency is from server to client.
  int32_t cs_latency = 4 * 1000;
  int32_t sc_latency = 5 * 1000;
  int32_t drift_per_round = 15;
  uint32_t half_rtt = (sc_latency + cs_latency) / 2;

  // Perform the initial setup.
  c.next_send = cbase;
  uint32_t t = send_next_ack_packet(&c, cbase, &s, sbase, cs_latency);
  s.next_send = sbase + t + 10 * 1000;

  uint32_t orig_server_start_rxtime = s.start_rxtime;
  WVPASSEQ(s.start_rxtime, sbase + cs_latency - s.usec_per_pkt);
  WVPASSEQ(s.start_rtxtime, cbase - c.usec_per_pkt);
  WVPASSEQ(ntohl(s.rx.clockdiff), 0);
  WVPASSEQ(s.lat_rx, 0);
  WVPASSEQ(s.lat_tx, 0);
  WVPASSEQ(s.min_cycle_rxdiff, 0);

  t = send_next_ack_packet(&s, sbase, &c, cbase, sc_latency);

  uint32_t orig_client_start_rxtime = c.start_rxtime;
  WVPASSEQ(c.start_rxtime, cbase + 2 * half_rtt + 10 * 1000 - c.usec_per_pkt);
  WVPASSEQ(c.start_rtxtime, sbase + cs_latency + 10 * 1000 - c.usec_per_pkt);
  WVPASSEQ(ntohl(c.rx.clockdiff), sbase - cbase + cs_latency);
  WVPASSEQ(c.lat_rx, half_rtt);
  WVPASSEQ(c.lat_tx, half_rtt);
  WVPASSEQ(c.min_cycle_rxdiff, 0);

  // Clock drift shows up as symmetric changes in one-way latency.
  int32_t total_drift = drift_per_round;
  t = send_next_ack_packet(&c, cbase, &s, sbase, cs_latency + total_drift);

  WVPASSEQ(s.start_rxtime, orig_server_start_rxtime);
  WVPASSEQ(s.start_rtxtime, cbase - c.usec_per_pkt);
  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency);
  WVPASSEQ(s.lat_rx, half_rtt + total_drift);
  WVPASSEQ(s.lat_tx, half_rtt);
  WVPASSEQ(s.min_cycle_rxdiff, 0);

  t = send_next_ack_packet(&s, sbase, &c, cbase, sc_latency - total_drift);

  WVPASSEQ(c.start_rxtime, cbase + 2 * half_rtt + 10 * 1000 - c.usec_per_pkt);
  WVPASSEQ(c.start_rtxtime,
           sbase + cs_latency + 10 * 1000 - c.usec_per_pkt);
  WVPASSEQ(ntohl(c.rx.clockdiff), sbase - cbase + cs_latency);
  WVPASSEQ(c.lat_rx, half_rtt - total_drift);
  WVPASSEQ(c.lat_tx, half_rtt + total_drift);
  WVPASSEQ(c.min_cycle_rxdiff, -drift_per_round);

  // Once we exceed -20us of drift, we adjust the client's start_rxtime.
  total_drift += drift_per_round;
  t = send_next_ack_packet(&c, cbase, &s, sbase, cs_latency + total_drift);

  WVPASSEQ(s.start_rxtime, orig_server_start_rxtime);
  WVPASSEQ(s.start_rtxtime, cbase - c.usec_per_pkt);
  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency);
  WVPASSEQ(s.lat_rx, half_rtt + total_drift);
  WVPASSEQ(s.lat_tx, half_rtt - drift_per_round);
  WVPASSEQ(s.min_cycle_rxdiff, 0);

  t = send_next_ack_packet(&s, sbase, &c, cbase, sc_latency - total_drift);

  int32_t clock_adj = total_drift;
  WVPASSEQ(c.start_rxtime,
           cbase + 2 * half_rtt + 10 * 1000 - c.usec_per_pkt - total_drift);
  WVPASSEQ(c.start_rtxtime, sbase + cs_latency + 10 * 1000 - c.usec_per_pkt);
  WVPASSEQ(ntohl(c.rx.clockdiff), sbase - cbase + cs_latency);
  WVPASSEQ(c.lat_rx, half_rtt - drift_per_round);
  WVPASSEQ(c.lat_tx, half_rtt + drift_per_round);
  WVPASSEQ(c.min_cycle_rxdiff, -drift_per_round);

  // Skip ahead to the next cycle.
  int packets_to_skip = 8;
  s.next_send += packets_to_skip * s.usec_per_pkt;
  s.next_rx_id += packets_to_skip;
  s.next_tx_id += packets_to_skip;
  c.next_send += packets_to_skip * c.usec_per_pkt;
  c.next_rx_id += packets_to_skip;
  c.next_tx_id += packets_to_skip;
  total_drift += packets_to_skip * drift_per_round;

  // At first we blame the rx latency for most of the drift.
  t = send_next_ack_packet(&c, cbase, &s, sbase, cs_latency + total_drift);

  // start_rxtime doesn't change here as the first cycle suppresses positive
  // min_cycle_rxdiff values.
  // TODO(pmccurdy): Should it?
  WVPASSEQ(s.start_rxtime, orig_server_start_rxtime);
  WVPASSEQ(s.start_rtxtime, cbase - c.usec_per_pkt);
  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency - clock_adj);
  WVPASSEQ(s.lat_rx, half_rtt + total_drift - drift_per_round);
  WVPASSEQ(s.lat_tx, half_rtt - drift_per_round);
  WVPASSEQ(s.min_cycle_rxdiff, INT_MAX);

  // After one round-trip, we divide the blame for the latency diff evenly.
  t = send_next_ack_packet(&s, sbase, &c, cbase, sc_latency - total_drift);

  WVPASSEQ(c.start_rxtime, orig_client_start_rxtime - total_drift);
  WVPASSEQ(c.start_rtxtime, sbase + cs_latency + 10 * 1000 - c.usec_per_pkt);
  WVPASSEQ(ntohl(c.rx.clockdiff), sbase - cbase + cs_latency);
  WVPASSEQ(c.lat_rx, half_rtt - total_drift / 2);
  WVPASSEQ(c.lat_tx, half_rtt + total_drift / 2);
  WVPASSEQ(c.min_cycle_rxdiff, INT_MAX);

  t = send_next_ack_packet(&c, cbase, &s, sbase, cs_latency + total_drift);

  WVPASSEQ(s.start_rxtime, orig_server_start_rxtime);
  WVPASSEQ(s.start_rtxtime, cbase - c.usec_per_pkt);
  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency - total_drift);
  WVPASSEQ(s.lat_rx, half_rtt + total_drift / 2);
  WVPASSEQ(s.lat_tx, half_rtt - total_drift / 2);
  // We also notice the difference in expected arrival times on the server...
  WVPASSEQ(s.min_cycle_rxdiff, total_drift);

  total_drift += drift_per_round;
  t = send_next_ack_packet(&s, sbase, &c, cbase, sc_latency - total_drift);
  // And on the client.  The client doesn't notice the total_drift rxdiff as it
  // was swallowed by the new cycle.
  WVPASSEQ(c.min_cycle_rxdiff, -drift_per_round);

  // Skip ahead to the next cycle.
  packets_to_skip = 8;
  s.next_send += packets_to_skip * s.usec_per_pkt;
  s.next_rx_id += packets_to_skip;
  s.next_tx_id += packets_to_skip;
  c.next_send += packets_to_skip * c.usec_per_pkt;
  c.next_rx_id += packets_to_skip;
  c.next_tx_id += packets_to_skip;
  total_drift += packets_to_skip * drift_per_round;
  int32_t drift_per_cycle = 10 * drift_per_round;
  t = send_next_ack_packet(&c, cbase, &s, sbase, cs_latency + total_drift);

  // The clock drift has worked its way into the RTT calculation.
  half_rtt = (cs_latency + sc_latency - drift_per_cycle) / 2;

  // Now start_rxtime has updated.
  WVPASSEQ(s.start_rxtime, orig_server_start_rxtime + drift_per_cycle);
  WVPASSEQ(s.start_rtxtime, cbase - c.usec_per_pkt);
  WVPASSEQ(ntohl(s.rx.clockdiff),
           cbase - sbase + sc_latency - drift_per_cycle);
  WVPASSEQ(s.lat_rx, half_rtt + total_drift);
  WVPASSEQ(s.lat_tx, half_rtt - drift_per_round);
  WVPASSEQ(s.min_cycle_rxdiff, INT_MAX);

  t = send_next_ack_packet(&s, sbase, &c, cbase, sc_latency - total_drift);

  WVPASSEQ(c.start_rxtime, orig_client_start_rxtime - total_drift);
  WVPASSEQ(c.start_rtxtime, sbase + cs_latency + 10 * 1000 - c.usec_per_pkt);
  WVPASSEQ(ntohl(c.rx.clockdiff), sbase - cbase + cs_latency + drift_per_cycle);
  WVPASSEQ(c.lat_rx, half_rtt + drift_per_round / 2);
  WVPASSEQ(c.lat_tx, half_rtt + total_drift / 2 + 1);
  WVPASSEQ(c.min_cycle_rxdiff, INT_MAX);
}

WVTEST_MAIN("Send and receive on sockets") {
  uint32_t cbase = 1400 * 1000;
  uint32_t sbase = 1600 * 1000;

  // Sockets for the client and server.
  int ssock, csock;
  struct addrinfo hints, *res;

  // Get local interface information.
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE | AI_V4MAPPED;
  int err = getaddrinfo(NULL, "0", &hints, &res);
  if (err != 0) {
    WVPASSEQ("Error from getaddrinfo: ", gai_strerror(err));
    return;
  }

  ssock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (!WVPASS(ssock >= 0)) {
    perror("server socket");
    return;
  }

  csock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (!WVPASS(csock >= 0)) {
    perror("client socket");
    return;
  }

  if (!WVPASS(!bind(ssock, res->ai_addr, res->ai_addrlen))) {
    perror("bind");
    return;
  }

  // Figure out the local port we got.
  struct sockaddr_storage listenaddr;
  socklen_t listenaddr_len = sizeof(listenaddr);
  memset(&listenaddr, 0, listenaddr_len);
  if (!WVPASS(!getsockname(ssock, (struct sockaddr *)&listenaddr,
                           &listenaddr_len))) {
    perror("getsockname");
    return;
  }

  printf("Bound server socket to port=%d\n",
         listenaddr.ss_family == AF_INET
             ? ntohs(((struct sockaddr_in *)&listenaddr)->sin_port)
             : ntohs(((struct sockaddr_in6 *)&listenaddr)->sin6_port));

  // Connect the client's socket.
  if (!WVPASS(
          !connect(csock, (struct sockaddr *)&listenaddr, listenaddr_len))) {
    perror("connect");
    return;
  }
  struct sockaddr_in6 caddr;
  socklen_t caddr_len = sizeof(caddr);
  memset(&caddr, 0, caddr_len);
  if (!WVPASS(!getsockname(csock, (struct sockaddr *)&caddr, &caddr_len))) {
    perror("getsockname");
    return;
  }
  char buf[128];
  inet_ntop(AF_INET6, (struct sockaddr *)&caddr, buf, sizeof(buf));
  printf("Created client connection on %s:%d\n", buf, ntohs(caddr.sin6_port));

  // All active sessions for the client and server.
  Sessions c;
  Sessions s;
  uint32_t usec_per_pkt = 100 * 1000;

  int is_server = 1;
  int is_client = 0;

  s.MaybeRotateCookieSecrets(sbase, is_server);
  // TODO(pmccurdy): Remove +1?
  c.NewSession(cbase + 1, usec_per_pkt, &listenaddr, listenaddr_len);

  // Send the initial handshake packet.
  Session &cSession = c.session_map.begin()->second;
  uint32_t t = cSession.next_send - cbase;
  WVPASS(!send_waiting_packets(&c, csock, cbase + t, is_client));

  WVPASSEQ(cSession.handshake_retry_count, 0);

  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(ssock, &rfds);
  struct timeval tv = {0, 0};
  int nfds = select(ssock + 1, &rfds, NULL, NULL, &tv);
  WVPASSEQ(nfds, 1);

  WVPASS(!read_incoming_packet(&s, ssock, sbase, is_server));

  // The server returns its handshake cookie immediately.
  FD_ZERO(&rfds);
  FD_SET(csock, &rfds);
  nfds = select(csock + 1, &rfds, NULL, NULL, &tv);
  WVPASSEQ(nfds, 1);

  // Eat the packet before the client can see it.
  Packet p;
  WVPASSEQ(recv(csock, &p, sizeof(p), 0), 540);

  // The client doesn't send more packets until the handshake timeout expires.
  t += Session::handshake_timeout_usec - 1;
  WVPASS(!send_waiting_packets(&c, csock, cbase + t, is_client));
  FD_ZERO(&rfds);
  FD_SET(csock, &rfds);
  nfds = select(csock + 1, &rfds, NULL, NULL, &tv);
  WVPASSEQ(nfds, 0);

  // Wait for the client to time out and resend the initial handshake packet.
  t += 1;
  WVPASS(!send_waiting_packets(&c, csock, cbase + t, is_client));

  FD_ZERO(&rfds);
  FD_SET(ssock, &rfds);
  nfds = select(ssock + 1, &rfds, NULL, NULL, &tv);
  WVPASSEQ(nfds, 1);

  // The server resends its cookie immediately.
  WVPASS(!read_incoming_packet(&s, ssock, sbase, is_server));

  // The server doesn't store any state for unverified clients
  WVPASSEQ(s.session_map.size(), 0);

  // Let the client read the cookie, establishing the connection.
  WVPASS(!read_incoming_packet(&c, csock, cbase + t, is_client));
  WVPASSEQ(cSession.next_tx_id, 1);

  uint32_t cs_latency = 4000;
  uint32_t sc_latency = 5000;

  WVPASSEQ(cSession.next_send, cbase + t);
  t = cSession.next_send - cbase - 1;
  WVPASS(!send_waiting_packets(&c, csock, cbase + t, is_client));

  // Verify we didn't send a packet before its time.
  FD_ZERO(&rfds);
  FD_SET(ssock, &rfds);
  nfds = select(ssock + 1, &rfds, NULL, NULL, &tv);
  WVPASSEQ(nfds, 0);

  // Send a packet in each direction.  The server can now verify the client.
  t += 1;
  WVPASSEQ(cSession.next_tx_id, 1);
  WVPASS(!send_waiting_packets(&c, csock, cbase + t, is_client));
  WVPASSEQ(cSession.next_tx_id, 2);

  FD_ZERO(&rfds);
  FD_SET(ssock, &rfds);
  nfds = select(ssock + 1, &rfds, NULL, NULL, &tv);
  WVPASSEQ(nfds, 1);

  t += cs_latency;
  WVPASS(!read_incoming_packet(&s, ssock, sbase + t, is_server));
  WVPASSEQ(s.session_map.size(), 1);
  WVPASSEQ(s.next_sends.size(), 1);
  WVPASSEQ(s.next_send_time(), sbase + t + 10 * 1000);

  WVPASSEQ(s.session_map.size(), 1);
  Session &sSession = s.session_map.begin()->second;
  WVPASS(sSession.remoteaddr_len > 0);
  WVPASSEQ(sSession.next_tx_id, 1);
  WVPASSEQ(ntohl(sSession.rx.id), 1);

  t = s.next_send_time() - sbase;
  WVPASS(!send_waiting_packets(&s, ssock, sbase + t, is_server));
  WVPASSEQ(s.next_send_time(), sbase + t + sSession.usec_per_pkt);
  WVPASSEQ(sSession.next_tx_id, 2);

  t += sc_latency;
  WVPASS(!read_incoming_packet(&c, csock, cbase + t, is_client));
  WVPASSEQ(cSession.lat_rx_count, 1);

  // Verify we reject garbage data.
  memset(&p, 0, sizeof(p));
  if (!WVPASSEQ(send(csock, &p, sizeof(p), 0), sizeof(p))) {
    perror("sendto");
    return;
  }

  WVPASSEQ(read_incoming_packet(&s, ssock, sbase + t, is_server), EINVAL);

  // Make a new client, who sends more frequently, getting a new source port.
  // Also establish an upper limit, to verify that the server enforces it.
  Sessions c2;
  set_packets_per_sec(4e6/usec_per_pkt);
  c2.NewSession(cbase, usec_per_pkt/10, &listenaddr, listenaddr_len);
  int c2sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (!WVPASS(c2sock > 0)) {
    perror("client socket 2");
    return;
  }
  if (!WVPASS(
          !connect(c2sock, (struct sockaddr *)&listenaddr, listenaddr_len))) {
    perror("connect");
    return;
  }
  struct sockaddr_in6 c2addr;
  socklen_t c2addr_len = sizeof(c2addr);
  memset(&c2addr, 0, c2addr_len);
  if (!WVPASS(!getsockname(c2sock, (struct sockaddr *)&c2addr, &c2addr_len))) {
    perror("getsockname");
    return;
  }
  inet_ntop(AF_INET6, (struct sockaddr *)&c2addr, buf, sizeof(buf));
  printf("Created new client connection on %s:%d\n", buf,
         ntohs(c2addr.sin6_port));

  Session &c2Session = c2.session_map.begin()->second;
  // Perform the handshake dance so the server knows we're legit.
  prepare_tx_packet(&c2Session);
  WVPASS(!send_packet(&c2Session, c2sock, is_client));
  t = cs_latency;
  WVPASS(!read_incoming_packet(&s, ssock, sbase+t, is_server));
  t += sc_latency;
  WVPASS(!read_incoming_packet(&c2, c2sock, cbase+t, is_client));

  WVPASSEQ(c2Session.usec_per_pkt, usec_per_pkt/4);

  // Now we can send a validated packet to the server.
  t = c2Session.next_send - cbase;
  WVPASS(!send_waiting_packets(&c2, c2sock, cbase + t, is_client));

  t += cs_latency;

  // Check that a new client is added to the server's state, and it will be sent
  // next.
  WVPASS(!read_incoming_packet(&s, ssock, sbase + t, is_server));
  WVPASSEQ(s.session_map.size(), 2);
  WVPASSEQ(s.next_sends.size(), 2);
  WVPASSEQ(s.next_send_time(), sbase + t + 10 * 1000);

  // Cleanup
  close(ssock);
  close(csock);
  close(c2sock);
  freeaddrinfo(res);
}

WVTEST_MAIN("Cookie Validation") {
  struct addrinfo hints, *res;

  // Get local interface information.
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE | AI_V4MAPPED;
  int err = getaddrinfo(NULL, "0", &hints, &res);
  if (err != 0) {
    WVPASSEQ("Error from getaddrinfo: ", gai_strerror(err));
    return;
  }

  // Set up a socket
  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);
  memset(&addr, 0, addr_len);
  int sock;
  sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (!WVPASS(sock >= 0)) {
    perror("socket");
    return;
  }
  if (!WVPASS(!getsockname(sock, (struct sockaddr *)&addr, &addr_len))) {
    perror("getsockname");
    return;
  }

  Sessions s;
  uint32_t epoch = 1;
  s.RotateCookieSecrets(epoch);
  Packet p;
  memset(&p, 0, sizeof(p));
  WVFAIL(s.CalculateCookie(&p, &addr, addr_len));

  p.packet_type = PACKET_TYPE_HANDSHAKE;
  p.usec_per_pkt = 100000;
  WVPASS(s.CalculateCookie(&p, &addr, addr_len));

  // We validate cookies we generate.
  WVPASS(s.ValidateCookie(&p, &addr, addr_len));

  // Validation fails after changing the IP port or address.
  sockaddr_storage changed_addr;
  memcpy(&changed_addr, &addr, addr_len);
  ((sockaddr_in6 *)&changed_addr)->sin6_port++;
  WVFAIL(s.ValidateCookie(&p, &changed_addr, addr_len));

  memcpy(&changed_addr, &addr, addr_len);
  ((sockaddr_in6 *)&changed_addr)->sin6_addr.s6_addr[0]++;
  WVFAIL(s.ValidateCookie(&p, &changed_addr, addr_len));

  // Validation fails after changing the usec_per_pkt.
  p.usec_per_pkt++;
  WVFAIL(s.ValidateCookie(&p, &addr, addr_len));
  p.usec_per_pkt--;

  // Validation fails after plain modifying the cookie.
  p.data.handshake.cookie[0]++;
  WVFAIL(s.ValidateCookie(&p, &changed_addr, addr_len));
  p.data.handshake.cookie[0]--;

  // Cookies generated with the previous secret still validate.
  epoch++;
  s.RotateCookieSecrets(epoch);
  WVPASS(s.ValidateCookie(&p, &addr, addr_len));

  // But secrets older than that don't validate.
  epoch++;
  s.RotateCookieSecrets(epoch);
  WVFAIL(s.ValidateCookie(&p, &addr, addr_len));

  // Cleanup
  close(sock);
  freeaddrinfo(res);
}

WVTEST_MAIN("Exponential Handshake Backoff") {
  struct addrinfo hints, *res;

  // Get local interface information.
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE | AI_V4MAPPED;
  int err = getaddrinfo(NULL, "0", &hints, &res);
  if (err != 0) {
    WVPASSEQ("Error from getaddrinfo: ", gai_strerror(err));
    return;
  }

  // Set up a socket
  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);
  memset(&addr, 0, addr_len);
  int sock;
  sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (!WVPASS(sock >= 0)) {
    perror("socket");
    return;
  }
  if (!WVPASS(!getsockname(sock, (struct sockaddr *)&addr, &addr_len))) {
    perror("getsockname");
    return;
  }

  uint32_t cbase = 400*1000;
  uint32_t usec_per_pkt = 100 * 1000;
  Sessions c;
  c.NewSession(cbase, usec_per_pkt, &addr, addr_len);
  Session &cSession = c.session_map.begin()->second;
  WVPASSEQ(cSession.next_send, cbase);

  // Test that we resend handshake packets on an exponential backoff schedule,
  // up until round 10.
  int is_client = 0;
  send_packet(&cSession, sock, is_client);
  WVPASSEQ(cSession.handshake_state, Session::HANDSHAKE_REQUESTED);
  WVPASSEQ(cSession.handshake_retry_count, 0);
  WVPASSEQ(cSession.next_send, cbase + Session::handshake_timeout_usec);

  uint32_t t = cSession.next_send;
  send_packet(&cSession, sock, is_client);
  WVPASSEQ(cSession.handshake_retry_count, 1);
  WVPASSEQ(cSession.next_send, t + 2 * Session::handshake_timeout_usec);

  t = cSession.next_send;
  send_packet(&cSession, sock, is_client);
  WVPASSEQ(cSession.handshake_retry_count, 2);
  WVPASSEQ(cSession.next_send, t + 4 * Session::handshake_timeout_usec);

  t = cSession.next_send;
  send_packet(&cSession, sock, is_client);
  WVPASSEQ(cSession.handshake_retry_count, 3);
  WVPASSEQ(cSession.next_send, t + 8 * Session::handshake_timeout_usec);

  t = cSession.next_send;
  send_packet(&cSession, sock, is_client);
  WVPASSEQ(cSession.handshake_retry_count, 4);
  WVPASSEQ(cSession.next_send, t + 16 * Session::handshake_timeout_usec);

  t = cSession.next_send;
  send_packet(&cSession, sock, is_client);
  WVPASSEQ(cSession.handshake_retry_count, 5);
  WVPASSEQ(cSession.next_send, t + 32 * Session::handshake_timeout_usec);

  t = cSession.next_send;
  send_packet(&cSession, sock, is_client);
  WVPASSEQ(cSession.handshake_retry_count, 6);
  WVPASSEQ(cSession.next_send, t + 64 * Session::handshake_timeout_usec);

  t = cSession.next_send;
  send_packet(&cSession, sock, is_client);
  WVPASSEQ(cSession.handshake_retry_count, 7);
  WVPASSEQ(cSession.next_send, t + 128 * Session::handshake_timeout_usec);

  t = cSession.next_send;
  send_packet(&cSession, sock, is_client);
  WVPASSEQ(cSession.handshake_retry_count, 8);
  WVPASSEQ(cSession.next_send, t + 256 * Session::handshake_timeout_usec);

  t = cSession.next_send;
  send_packet(&cSession, sock, is_client);
  WVPASSEQ(cSession.handshake_retry_count, 9);
  WVPASSEQ(cSession.next_send, t + 512 * Session::handshake_timeout_usec);

  t = cSession.next_send;
  send_packet(&cSession, sock, is_client);
  WVPASSEQ(cSession.handshake_retry_count, 10);
  WVPASSEQ(cSession.next_send, t + 1024 * Session::handshake_timeout_usec);

  t = cSession.next_send;
  send_packet(&cSession, sock, is_client);
  WVPASSEQ(cSession.handshake_retry_count, 11);
  WVPASSEQ(cSession.next_send, t + 1024 * Session::handshake_timeout_usec);

  // Cleanup
  close(sock);
  freeaddrinfo(res);
}
