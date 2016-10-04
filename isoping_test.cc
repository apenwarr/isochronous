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
#include <limits.h>
#include <stdio.h>

#include <wvtest.h>

#include "isoping.h"

uint32_t send_next_packet(Session *from, uint32_t from_base,
                          Session *to, uint32_t to_base, uint32_t latency) {
  uint32_t t = from->next_send - from_base;
  prepare_tx_packet(from);
  to->rx = from->tx;
  from->next_send += from->usec_per_pkt;
  t += latency;
  handle_packet(to, to_base + t);
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

  // The states of the client and server.
  struct Session c(cbase);
  struct Session s(sbase);

  // One-way latencies: cs_latency is the latency from client to server;
  // sc_latency is from server to client.
  uint32_t cs_latency = 24 * 1000;
  uint32_t sc_latency = 25 * 1000;
  uint32_t half_rtt = (sc_latency + cs_latency) / 2;

  // Elapsed time, relative to the base time for each clock.
  uint32_t t = 0;

  // Send the initial packet from client to server.  This isn't enough to let us
  // draw any useful latency conclusions.
  // TODO(pmccurdy): Setting next_send is duplicating some work done in the main
  // loop / send_packet.  Extract that into somewhere testable, then test it.
  c.next_send = cbase;
  t = send_next_packet(&c, cbase, &s, sbase, cs_latency);
  uint32_t rxtime = sbase + t;
  s.next_send = rxtime + 10 * 1000;

  printf("last_rxtime: %d\n", s.last_rxtime);
  printf("min_cycle_rxdiff: %d\n", s.min_cycle_rxdiff);
  WVPASSEQ(s.rx.clockdiff, 0);
  WVPASSEQ(s.last_rxtime, rxtime);
  WVPASSEQ(s.min_cycle_rxdiff, 0);
  WVPASSEQ(ntohl(s.tx.acks[0].id), 1);
  WVPASSEQ(s.next_txack_index, 1);
  WVPASSEQ(ntohl(s.tx.acks[ntohl(s.tx.first_ack)].id), 1);
  WVPASSEQ(ntohl(s.tx.acks[ntohl(s.tx.first_ack)].rxtime), rxtime);
  WVPASSEQ(s.start_rxtime, rxtime - c.usec_per_pkt);
  WVPASSEQ(s.start_rtxtime, cbase - c.usec_per_pkt);
  WVPASSEQ(s.next_send, rxtime + 10 * 1000);

  // Reply to the client.
  t = send_next_packet(&s, sbase, &c, cbase, sc_latency);

  // Now we have enough data to figure out latencies on the client.
  rxtime = cbase + t;
  WVPASSEQ(c.start_rxtime, rxtime - s.usec_per_pkt);
  WVPASSEQ(c.start_rtxtime, sbase + cs_latency + 10 * 1000 - s.usec_per_pkt);
  WVPASSEQ(c.min_cycle_rxdiff, 0);
  WVPASSEQ(ntohl(c.rx.clockdiff), sbase - cbase + cs_latency);
  WVPASSEQ(ntohl(c.tx.acks[ntohl(c.tx.first_ack)].id), 1);
  WVPASSEQ(ntohl(c.tx.acks[ntohl(c.tx.first_ack)].rxtime), rxtime);
  WVPASSEQ(c.num_lost, 0);
  WVPASSEQ(c.lat_tx_count, 1);
  WVPASSEQ(c.lat_tx, half_rtt);
  WVPASSEQ(c.lat_rx_count, 1);
  WVPASSEQ(c.lat_rx, half_rtt);
  WVPASSEQ(c.num_lost, 0);

  // Round 2
  t = send_next_packet(&c, cbase, &s, sbase, cs_latency);
  rxtime = sbase + t;

  // Now the server also knows latencies.
  WVPASSEQ(s.start_rxtime, sbase + cs_latency - s.usec_per_pkt);
  WVPASSEQ(s.start_rtxtime, cbase - c.usec_per_pkt);
  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency);
  WVPASSEQ(ntohl(s.tx.acks[ntohl(s.tx.first_ack)].id), 2);
  WVPASSEQ(ntohl(s.tx.acks[ntohl(s.tx.first_ack)].rxtime), rxtime);
  WVPASSEQ(s.num_lost, 0);
  WVPASSEQ(s.lat_tx_count, 1);
  WVPASSEQ(s.lat_tx, half_rtt);
  WVPASSEQ(s.lat_rx_count, 1);
  WVPASSEQ(s.lat_rx, half_rtt);
  WVPASSEQ(s.num_lost, 0);

  // Increase the latencies in both directions, reply to client.
  int32_t latency_diff = 10 * 1000;
  t = send_next_packet(&s, sbase, &c, cbase, sc_latency + latency_diff);

  rxtime = cbase + t;
  WVPASSEQ(ntohl(s.tx.clockdiff), real_clockdiff + cs_latency);
  WVPASSEQ(c.start_rxtime,
           rxtime - ntohl(s.tx.id) * s.usec_per_pkt - latency_diff);
  WVPASSEQ(c.start_rtxtime, sbase + cs_latency + 10 * 1000 - s.usec_per_pkt);
  WVPASSEQ(ntohl(c.tx.acks[ntohl(c.tx.first_ack)].id), 2);
  WVPASSEQ(ntohl(c.tx.acks[ntohl(c.tx.first_ack)].rxtime), rxtime);
  WVPASSEQ(c.num_lost, 0);
  WVPASSEQ(c.lat_tx_count, 2);
  WVPASSEQ(c.lat_tx, half_rtt);
  WVPASSEQ(c.lat_rx_count, 2);
  WVPASSEQ(c.lat_rx, half_rtt + latency_diff);
  WVPASSEQ(c.num_lost, 0);

  // Client replies with increased latency, server notices.
  t = send_next_packet(&c, cbase, &s, sbase, cs_latency + latency_diff);

  rxtime = sbase + t;
  WVPASSEQ(ntohl(c.tx.clockdiff), - real_clockdiff + sc_latency);
  WVPASSEQ(s.start_rxtime, sbase + cs_latency - s.usec_per_pkt);
  WVPASSEQ(s.start_rtxtime, cbase - c.usec_per_pkt);
  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency);
  WVPASSEQ(ntohl(s.tx.acks[ntohl(s.tx.first_ack)].id), 3);
  WVPASSEQ(ntohl(s.tx.acks[ntohl(s.tx.first_ack)].rxtime), rxtime);
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

  t = send_next_packet(&c, cbase, &s, sbase, cs_latency + latency_diff);

  rxtime = sbase + t;
  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency);
  WVPASSEQ(ntohl(s.tx.acks[ntohl(s.tx.first_ack)].id), 3);
  WVPASSEQ(ntohl(s.tx.acks[ntohl(s.tx.first_ack)].rxtime),
           rxtime - s.usec_per_pkt);
  WVPASSEQ(s.num_lost, 0);
  WVPASSEQ(s.lat_tx_count, 2);
  WVPASSEQ(s.lat_tx, half_rtt + latency_diff);
  WVPASSEQ(s.lat_rx_count, 3);
  WVPASSEQ(s.lat_rx, half_rtt + latency_diff);
  WVPASSEQ(s.num_lost, 0);

  // Remove the extra latency from server->client, send the next packet, have
  // the client receive it and notice the lost packet and reduced latency.
  t = send_next_packet(&s, sbase, &c, cbase, sc_latency);

  rxtime = cbase + t;
  WVPASSEQ(ntohl(c.tx.acks[ntohl(c.tx.first_ack)].id), 4);
  WVPASSEQ(ntohl(c.tx.acks[ntohl(c.tx.first_ack)].rxtime), rxtime);
  WVPASSEQ(c.num_lost, 1);
  WVPASSEQ(c.lat_tx_count, 4);
  WVPASSEQ(c.lat_tx, half_rtt + latency_diff);
  WVPASSEQ(c.lat_rx_count, 3);
  WVPASSEQ(c.lat_rx, half_rtt);
  WVPASSEQ(c.num_lost, 1);

  // A tiny reduction in latency shows up in min_cycle_rxdiff.
  latency_diff = 0;
  int32_t latency_mini_diff = -15;
  t = send_next_packet(&c, cbase, &s, sbase, cs_latency + latency_mini_diff);

  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency);
  WVPASSEQ(s.min_cycle_rxdiff, latency_mini_diff);
  WVPASSEQ(s.start_rxtime, sbase + cs_latency - s.usec_per_pkt);
  WVPASSEQ(s.lat_tx, half_rtt);
  WVPASSEQ(s.lat_rx, half_rtt + latency_mini_diff);

  t = send_next_packet(&s, sbase, &c, cbase, sc_latency + latency_mini_diff);

  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency);
  WVPASSEQ(c.min_cycle_rxdiff, latency_mini_diff);
  WVPASSEQ(c.lat_tx, half_rtt + latency_mini_diff);
  WVPASSEQ(c.lat_rx, half_rtt + latency_mini_diff);

  // Reduce the latency dramatically, verify that both sides see it, and the
  // start time is modified (not the min_cycle_rxdiff).
  latency_diff = -22 * 1000;
  t = send_next_packet(&c, cbase, &s, sbase, cs_latency + latency_diff);

  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency);
  WVPASSEQ(s.min_cycle_rxdiff, latency_mini_diff);
  // We see half the latency diff applied to each side of the connection because
  // the reduction in latency creates a time paradox, rebasing the start time
  // and recalculating the RTT.
  WVPASSEQ(s.start_rxtime, sbase + cs_latency + latency_diff - s.usec_per_pkt);
  WVPASSEQ(s.lat_tx, half_rtt + latency_diff/2 + latency_mini_diff);
  WVPASSEQ(s.lat_rx, half_rtt + latency_diff/2);

  t = send_next_packet(&s, sbase, &c, cbase, sc_latency + latency_diff);

  // Now we see the new latency applied to both sides.
  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency);
  WVPASSEQ(c.min_cycle_rxdiff, latency_mini_diff);
  WVPASSEQ(c.lat_tx, half_rtt + latency_diff);
  WVPASSEQ(c.lat_rx, half_rtt + latency_diff);

  // Restore latency on one side of the connection, verify that we track it on
  // only one side and we've improved our clock sync.
  t = send_next_packet(&c, cbase, &s, sbase, cs_latency);

  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency + latency_diff);
  WVPASSEQ(s.lat_tx, half_rtt + latency_diff);
  WVPASSEQ(s.lat_rx, half_rtt);

  // And double-check that the other side also sees the improved clock sync and
  // one-sided latency on the correct side.
  t = send_next_packet(&s, sbase, &c, cbase, sc_latency + latency_diff);

  WVPASSEQ(ntohl(c.rx.clockdiff), sbase - cbase + cs_latency + latency_diff);
  WVPASSEQ(c.lat_tx, half_rtt);
  WVPASSEQ(c.lat_rx, half_rtt + latency_diff);
}

// Verify that isoping handles clocks ticking at different rates.
WVTEST_MAIN("isoping clock drift") {
  uint32_t cbase = 1400 * 1000;
  uint32_t sbase = 1600 * 1000;

  // The states of the client and server.
  struct Session c(cbase);
  struct Session s(sbase);
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
  uint32_t t = send_next_packet(&c, cbase, &s, sbase, cs_latency);
  s.next_send = sbase + t + 10 * 1000;

  uint32_t orig_server_start_rxtime = s.start_rxtime;
  WVPASSEQ(s.start_rxtime, sbase + cs_latency - s.usec_per_pkt);
  WVPASSEQ(s.start_rtxtime, cbase - c.usec_per_pkt);
  WVPASSEQ(ntohl(s.rx.clockdiff), 0);
  WVPASSEQ(s.lat_rx, 0);
  WVPASSEQ(s.lat_tx, 0);
  WVPASSEQ(s.min_cycle_rxdiff, 0);

  t = send_next_packet(&s, sbase, &c, cbase, sc_latency);

  uint32_t orig_client_start_rxtime = c.start_rxtime;
  WVPASSEQ(c.start_rxtime, cbase + 2 * half_rtt + 10 * 1000 - c.usec_per_pkt);
  WVPASSEQ(c.start_rtxtime, sbase + cs_latency + 10 * 1000 - c.usec_per_pkt);
  WVPASSEQ(ntohl(c.rx.clockdiff), sbase - cbase + cs_latency);
  WVPASSEQ(c.lat_rx, half_rtt);
  WVPASSEQ(c.lat_tx, half_rtt);
  WVPASSEQ(c.min_cycle_rxdiff, 0);

  // Clock drift shows up as symmetric changes in one-way latency.
  int32_t total_drift = drift_per_round;
  t = send_next_packet(&c, cbase, &s, sbase, cs_latency + total_drift);

  WVPASSEQ(s.start_rxtime, orig_server_start_rxtime);
  WVPASSEQ(s.start_rtxtime, cbase - c.usec_per_pkt);
  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency);
  WVPASSEQ(s.lat_rx, half_rtt + total_drift);
  WVPASSEQ(s.lat_tx, half_rtt);
  WVPASSEQ(s.min_cycle_rxdiff, 0);

  t = send_next_packet(&s, sbase, &c, cbase, sc_latency - total_drift);

  WVPASSEQ(c.start_rxtime, cbase + 2 * half_rtt + 10 * 1000 - c.usec_per_pkt);
  WVPASSEQ(c.start_rtxtime,
           sbase + cs_latency + 10 * 1000 - c.usec_per_pkt);
  WVPASSEQ(ntohl(c.rx.clockdiff), sbase - cbase + cs_latency);
  WVPASSEQ(c.lat_rx, half_rtt - total_drift);
  WVPASSEQ(c.lat_tx, half_rtt + total_drift);
  WVPASSEQ(c.min_cycle_rxdiff, -drift_per_round);

  // Once we exceed -20us of drift, we adjust the client's start_rxtime.
  total_drift += drift_per_round;
  t = send_next_packet(&c, cbase, &s, sbase, cs_latency + total_drift);

  WVPASSEQ(s.start_rxtime, orig_server_start_rxtime);
  WVPASSEQ(s.start_rtxtime, cbase - c.usec_per_pkt);
  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency);
  WVPASSEQ(s.lat_rx, half_rtt + total_drift);
  WVPASSEQ(s.lat_tx, half_rtt - drift_per_round);
  WVPASSEQ(s.min_cycle_rxdiff, 0);

  t = send_next_packet(&s, sbase, &c, cbase, sc_latency - total_drift);

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
  t = send_next_packet(&c, cbase, &s, sbase, cs_latency + total_drift);

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
  t = send_next_packet(&s, sbase, &c, cbase, sc_latency - total_drift);

  WVPASSEQ(c.start_rxtime, orig_client_start_rxtime - total_drift);
  WVPASSEQ(c.start_rtxtime, sbase + cs_latency + 10 * 1000 - c.usec_per_pkt);
  WVPASSEQ(ntohl(c.rx.clockdiff), sbase - cbase + cs_latency);
  WVPASSEQ(c.lat_rx, half_rtt - total_drift / 2);
  WVPASSEQ(c.lat_tx, half_rtt + total_drift / 2);
  WVPASSEQ(c.min_cycle_rxdiff, INT_MAX);

  t = send_next_packet(&c, cbase, &s, sbase, cs_latency + total_drift);

  WVPASSEQ(s.start_rxtime, orig_server_start_rxtime);
  WVPASSEQ(s.start_rtxtime, cbase - c.usec_per_pkt);
  WVPASSEQ(ntohl(s.rx.clockdiff), cbase - sbase + sc_latency - total_drift);
  WVPASSEQ(s.lat_rx, half_rtt + total_drift / 2);
  WVPASSEQ(s.lat_tx, half_rtt - total_drift / 2);
  // We also notice the difference in expected arrival times on the server...
  WVPASSEQ(s.min_cycle_rxdiff, total_drift);

  total_drift += drift_per_round;
  t = send_next_packet(&s, sbase, &c, cbase, sc_latency - total_drift);
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
  t = send_next_packet(&c, cbase, &s, sbase, cs_latency + total_drift);

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

  t = send_next_packet(&s, sbase, &c, cbase, sc_latency - total_drift);

  WVPASSEQ(c.start_rxtime, orig_client_start_rxtime - total_drift);
  WVPASSEQ(c.start_rtxtime, sbase + cs_latency + 10 * 1000 - c.usec_per_pkt);
  WVPASSEQ(ntohl(c.rx.clockdiff), sbase - cbase + cs_latency + drift_per_cycle);
  WVPASSEQ(c.lat_rx, half_rtt + drift_per_round / 2);
  WVPASSEQ(c.lat_tx, half_rtt + total_drift / 2 + 1);
  WVPASSEQ(c.min_cycle_rxdiff, INT_MAX);

  t = send_next_packet(&c, cbase, &s, sbase, cs_latency + total_drift);

}
