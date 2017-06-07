/*
 * Copyright 2017 Google Inc. All rights reserved.
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

/* A version of isoping_main.cc to be used when fuzzing.  Reads the fuzz test
 * case from standard input, writes it to the socket, then exits once processing
 * is finished.*/

#include "isoping.h"

#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <time.h>
#include <unistd.h>

// Removes sources of nondeterminism from the Sessions code, so fuzzers can
// detect which code paths are affected by inputs.
class DeterministicSessions : public Sessions {
 public:
  DeterministicSessions() : Sessions() {
    // Make the cookie secret data deterministic.
    prev_cookie_epoch = 1;
    cookie_epoch = 2;
    memset(&prev_cookie_secret, 0, sizeof(prev_cookie_secret));
    memset(&cookie_secret, 0, sizeof(cookie_secret));
    prev_cookie_secret[0] = 1;
    cookie_secret[0] = 2;
  }
  ~DeterministicSessions() {}

  // Don't rotate the cookie secrets, it confuses the fuzzer.
  virtual void MaybeRotateCookieSecrets(uint32_t now, int is_server) {
  }

  // Force the incoming cookie to be valid, then call the real validation
  // routine.  This ensures we test the real routine, without the fuzzer having
  // to generate valid cookies on its own.
  virtual bool ValidateCookie(Packet *p, struct sockaddr_storage *addr,
                              socklen_t addr_len) {
    Packet golden;
    golden.packet_type = PACKET_TYPE_HANDSHAKE;
    golden.usec_per_pkt = p->usec_per_pkt;
    p->data.handshake.cookie_epoch = cookie_epoch;
    CalculateCookieWithSecret(&golden, addr, addr_len, cookie_secret,
                              sizeof(cookie_secret));
    memcpy(p->data.handshake.cookie, golden.data.handshake.cookie, COOKIE_SIZE);
    return Sessions::ValidateCookie(p, addr, addr_len);
  }
};

int main(int argc, char **argv) {
  DeterministicSessions dsessions;
  // Read data from stdin
  fprintf(stderr, "Running fuzz code.\n");
  unsigned char buf[10 * sizeof(Packet)];
  memset(buf, 0, sizeof(buf));
  int insize = read(0, buf, sizeof(buf));
  fprintf(stderr, "Read %d bytes from stdin.\n", insize);

  struct addrinfo hints;
  struct addrinfo *res;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE | AI_V4MAPPED;
  int err = getaddrinfo(NULL, "0", &hints, &res);
  if (err != 0) {
    perror("getaddrinfo");
    return 1;
  }

  int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (sock < 0) {
    perror("socket");
    return 2;
  }

  if (bind(sock, res->ai_addr, res->ai_addrlen)) {
    perror("bind");
    return 3;
  }

  // Figure out the local port we got.
  struct sockaddr_storage listenaddr;
  socklen_t listenaddr_len = sizeof(listenaddr);
  memset(&listenaddr, 0, listenaddr_len);
  if (getsockname(sock, (struct sockaddr *)&listenaddr, &listenaddr_len)) {
    perror("getsockname");
    return 4;
  }

  // Send each incoming packet from a different client port.
  while (insize > 0) {
    int csock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (csock < 0) {
      perror("client socket");
      return 5;
    }
    if (connect(csock, (struct sockaddr *)&listenaddr, listenaddr_len)) {
      perror("connect");
      return 6;
    }

    int packet_len = std::min((unsigned long)insize, sizeof(Packet));
    sendto(csock, buf, packet_len, 0, (struct sockaddr *)&listenaddr,
           listenaddr_len);
    insize -= packet_len;
    close(csock);
  }

  isoping_main(argc, argv, &dsessions, sock);
  close(sock);
  freeaddrinfo(res);
}
