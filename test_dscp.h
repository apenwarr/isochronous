#ifndef _TWD_TEST_DSCP
#define _TWD_TEST_DSCP

/* Test parameters for common diffserv values */

const uint8_t test_cs[]  = {
  7,
  IPTOS_DSCP_CS0,
  IPTOS_DSCP_CS1,
  IPTOS_DSCP_CS2,
  IPTOS_DSCP_CS3,
  IPTOS_DSCP_CS4,
  IPTOS_DSCP_CS5,
  IPTOS_DSCP_CS6,
  IPTOS_DSCP_CS7 
  } ;

/* Most linux 802.11e implementations honor the 
   below settings for the BE, BK, VO, and VI hw queues */

const uint8_t test_wifi[] = {
  4,
  IPTOS_DSCP_CS0, 
  IPTOS_DSCP_CS1,
  IPTOS_DSCP_CS5,
  IPTOS_DSCP_CS7, 
  } ; 

const uint8_t test_af[]   = { 
  12,
  IPTOS_DSCP_AF11, 
  IPTOS_DSCP_AF12, 
  IPTOS_DSCP_AF13,
  IPTOS_DSCP_AF21,
  IPTOS_DSCP_AF22,
  IPTOS_DSCP_AF23,
  IPTOS_DSCP_AF31,
  IPTOS_DSCP_AF32,
  IPTOS_DSCP_AF33,
  IPTOS_DSCP_AF41,
  IPTOS_DSCP_AF42,
  IPTOS_DSCP_AF43,
  } ;

const uint8_t test_tos[]  = {
  3,
  IPTOS_LOWDELAY,
  IPTOS_THROUGHPUT,
  IPTOS_RELIABILITY,
  };

const uint8_t test_all[]   = { 
  20,
  IPTOS_DSCP_AF11, 
  IPTOS_DSCP_AF12, 
  IPTOS_DSCP_AF13,
  IPTOS_DSCP_AF21,
  IPTOS_DSCP_AF22,
  IPTOS_DSCP_AF23,
  IPTOS_DSCP_AF31,
  IPTOS_DSCP_AF32,
  IPTOS_DSCP_AF33,
  IPTOS_DSCP_AF41,
  IPTOS_DSCP_AF42,
  IPTOS_DSCP_AF43,
  IPTOS_DSCP_EF,
  IPTOS_DSCP_CS0,
  IPTOS_DSCP_CS1,
  IPTOS_DSCP_CS2,
  IPTOS_DSCP_CS3,
  IPTOS_DSCP_CS4,
  IPTOS_DSCP_CS5,
  IPTOS_DSCP_CS6,
  IPTOS_DSCP_CS7 
  } ;

#endif
