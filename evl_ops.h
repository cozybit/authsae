#ifndef _EVL_OPS_H_
#define _EVL_OPS_H_

#define SRV_SEC(x) ((x)*1000000ULL)
#define SRV_MSEC(x) ((x)*1000ULL)
#define SRV_USEC(x) x

typedef unsigned long long timerid;

/* On 32-bit platforms an unsigned long only gives us:
 * 4294967295 us = 4294967 ms = 4294 s = 71 min
 * That's not very much time especially given that
 * we'd like to do some math using signed integers
 * so we use a long long.
 */
typedef unsigned long long microseconds;
typedef void (*fdcb)(int fd, void *data);
typedef void (*timercb)(void *data);

struct evl_ops {
  timerid (*add_timeout_with_jitter)(
      microseconds usec,
      timercb proc,
      void *data,
      microseconds jitter_usecs);
  timerid (*add_timeout)(microseconds usec, timercb proc, void *data);
  int (*rem_timeout)(timerid);
  int (*add_input)(int, void *, fdcb);
  void (*rem_input)(int);
};
#endif /* _EVL_OPS_H_ */
