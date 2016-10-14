/*
 * Copyright (c) Dan Harkins, 2008, 2009, 2010
 *
 *  Copyright holder grants permission for redistribution and use in source 
 *  and binary forms, with or without modification, provided that the 
 *  following conditions are met:
 *     1. Redistribution of source code must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in all source files.
 *     2. Redistribution in binary form must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in the documentation and/or other materials provided with the
 *        distribution.
 *     3. All advertising materials and documentation mentioning features
 *	  or use of this software must display the following acknowledgement:
 *
 *        "This product includes software written by
 *         Dan Harkins (dharkins at lounge dot org)"
 *
 *  "DISCLAIMER OF LIABILITY
 *  
 *  THIS SOFTWARE IS PROVIDED BY DAN HARKINS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INDUSTRIAL LOUNGE BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE."
 *
 * This license and distribution terms cannot be changed. In other words,
 * this code cannot simply be copied and put under a different distribution
 * license (including the GNU public license).
 */

#include "service.h"

#include <errno.h>
#include <openssl/rand.h>
#include <string.h>
#include <time.h>

#include "common.h"

#define SRV_TICK 1000000

#define IS_ZERO(t)	(!(t)->tv_sec && !(t)->tv_nsec)

#define NANOSECONDS_PER_SEC (1000000000)


static void timespec_to_timeval(struct timespec *spec, struct timeval *val) {
  val->tv_sec = spec->tv_sec;
  val->tv_usec = spec->tv_nsec / 1000;
}

static void normalise_time(struct timespec *t) {
   while (t->tv_nsec < 0) {
     t->tv_sec--;
     t->tv_nsec += NANOSECONDS_PER_SEC;
   }
   while (t->tv_nsec >= NANOSECONDS_PER_SEC) {
     t->tv_sec++;
     t->tv_nsec -= NANOSECONDS_PER_SEC;
   }

   /* t.tv_nsec in [0, NANOSECONDS_PER_SEC) */
}

/*
 * add_time()
 *	t1 += t2
 */
static void add_time(struct timespec *t1, struct timespec *t2) {
  t1->tv_sec += t2->tv_sec;
  t1->tv_nsec += t2->tv_nsec;
  normalise_time(t1);
}

/*
 * sub_time()
 *	t1 -= t2
 */
static void sub_time(struct timespec *t1, struct timespec *t2) {
  t1->tv_sec -= t2->tv_sec;
  t1->tv_nsec -= t2->tv_nsec;
  normalise_time(t1);

  if (t1->tv_sec < 0) {
    t1->tv_sec = 0;
    t1->tv_nsec = 0;
  }
}

/*
 * cmp_time()
 *	compare times, return -1, 0, 1 if t1 < t2, t1 = t2, t1 > t2
 *	respectively. By definition, 0.0 means infinity.
 */
static int cmp_time(struct timespec *t1, struct timespec *t2) {
  /*
   * if both are zero they're equal but if only one of them
   * is zero that's the "older" one
   */
  if (IS_ZERO(t2)) {
    if (IS_ZERO(t1)) {
      return 0;
    } else {
      return -1; /* t1 is non-zero, t2 is older */
    }
  }
  if (IS_ZERO(t1)) {
    return 1; /* t2 is non-zero, t1 is older */
  }

  /*
   * neither are zero so compare them to see who's older
   */
  if (t1->tv_sec != t2->tv_sec) {
    return (t1->tv_sec - t2->tv_sec);
  }
  return (t1->tv_nsec - t2->tv_nsec);
}

/*
 * cmp_timers()
 *	callback for qsort() to put timers in ascending order
 */
static int
cmp_timers (struct timer *t1, struct timer *t2)
{
    return (cmp_time(&(t1->to), &(t2->to)));
}

/*
 * srv_add_timeout_with_jitter()
 *	add a timer with callback to a service context
 *      Returns a handle to the timer or 0 if we run out
 *      of timers.
 */
timerid
srv_add_timeout_with_jitter (service_context context, microseconds usec,
		 timercb proc, void *data, microseconds jitter_usecs)
{
    struct timespec right_now;
    timerid id;

    if (jitter_usecs) {
        long long rand_number, delta, new_usec;
        (void) RAND_pseudo_bytes((unsigned char *) &rand_number, sizeof(rand_number));
        delta = -(long long) jitter_usecs/2  + llabs(rand_number) % jitter_usecs;

        new_usec = (long long) usec + delta;
        if (new_usec < 0)
            usec = 1;
        else
            usec = (microseconds) new_usec;
    }

    if (context->ntimers >= NTIMERS) {
        sae_debug(SAE_DEBUG_ERR, "too many timers!\n");
        return 0;
    }
    context->timers[context->ntimers].to.tv_sec = usec/SRV_TICK;
    context->timers[context->ntimers].to.tv_nsec = 1000 * (usec - ((usec/SRV_TICK)*SRV_TICK));
    id = context->timers[context->ntimers].id = ++(context->timer_id);
    context->timers[context->ntimers].proc = proc;
    context->timers[context->ntimers].data = data;

    clock_gettime(CLOCK_MONOTONIC, &right_now);
    add_time(&(context->timers[context->ntimers].to), &right_now);
    context->ntimers++;
    qsort(context->timers, context->ntimers, sizeof(struct timer), (int (*)())cmp_timers);

    return id;
}

/*
 * srv_rem_timer()
 *	given a handle remove the timer from a service context
 */
int
srv_rem_timeout (service_context context, timerid id)
{
    int i;

    /*
     * timer id's should always be non-zero so if someone is trying to
     * cancel a zero timer it means he's trying to cancel an already
     * cancelled timer. Don't locate a timer with id = 0 and erroneously
     * decrement the number of timers, just return.
     */
    if (id == 0) {
        return 0;
    }
    for (i=0; i<NTIMERS; i++) {
	if (context->timers[i].id == id) {
	    context->timers[i].id = 0;
	    context->timers[i].to.tv_sec = context->timers[i].to.tv_nsec = 0;
	    if (context->ntimers > 1) {
		qsort(context->timers, context->ntimers, sizeof(struct timer),
		      (int (*)())cmp_timers);
	    }
	    context->ntimers--;
	    break;
	}
    }
    return (i < NTIMERS);
}

/*
 * srv_add_input()
 *	add an input with callback and data to a service context
 *	Returns 0 on success, -1 and ERANGE if we run out of bits.
 */
int
srv_add_input (service_context context, int fd, void *data, fdcb proc)
{
    int i, next = -1;

    /*
     * first see if there's any available, if not we add to the end and
     * bump the ninputs high-water-mark
     */

    for (i=0; i<context->ninputs; i++) {
	if (context->inputs[i].fd == fd) {
	    next = i;
	    break;
	}
    }
    if (next == -1) {
	if (i < NFDS) {
	    next = i;
	    context->ninputs++;
	} else {
	    errno = ERANGE;
	    return -1;
	}
    }
    FD_SET(fd, &context->readfds);
    FD_SET(fd, &context->exceptfds);
    context->inputs[next].fd = fd;
    context->inputs[next].proc = proc;
    context->inputs[next].data = data;
    return 0;
}

/*
 * srv_rem_input()
 *	remove an input from a service context
 */
void
srv_rem_input (service_context context, int fd)
{
    int i;

    for (i=0; i<context->ninputs; i++) {
	if (context->inputs[i].fd == fd) {
	    context->inputs[i].fd = 0;
	    context->ninputs--;
	    /*
	     * swap structures so it's contiguous 
	     */
	    context->inputs[i] = context->inputs[context->ninputs];
	    FD_CLR(fd, &context->readfds);
            FD_CLR(fd, &context->exceptfds);
	    return;
	}
    }
    return;
}

/*
 * srv_add_output()
 *	add an output with callback and data to a service context
 *	Returns 0 on success, -1 and ERANGE if we run out of bits.
 */
int
srv_add_output (service_context context, int fd, void *data, fdcb proc)
{
    int i, next = -1;
    
    /*
     * first see if there's any available, if not we add to the end and
     * bump the noutputs high-water-mark
     */
    for (i=0; i<context->noutputs; i++) {
	if (context->outputs[i].fd == fd) {
	    next = i;
	    break;
	}
    }
    if (next == -1) {
	if (i < NFDS) {
	    next = i;
	    context->noutputs++;
	} else {
	    errno = ERANGE;
	    return -1;
	}
    }
    FD_SET(fd, &context->writefds);
    context->outputs[next].fd = fd;
    context->outputs[next].proc = proc;
    context->outputs[next].data = data;
    return 0;
}

/*
 * srv_rem_output()
 *	remove an output from a service context
 */
void
srv_rem_output (service_context context, int fd)
{
    int i;

    for (i=0; i<context->noutputs; i++) {
	if (context->outputs[i].fd == fd) {
	    context->outputs[i].fd = 0;
	    context->noutputs--;
	    /*
	     * swap structures so it's contiguous
	     */
	    context->outputs[i] = context->outputs[context->noutputs];
	    FD_CLR(fd, &context->writefds);
	    return;
	}
    }
    return;
}

/*
 * srv_add_exceptor()
 *      add a callback to deal with a bad/stale/messed-up socket.
 *      The callback should remove the socket from the service context.
 */
void
srv_add_exceptor (service_context sc, fdcb proc)
{
    sc->exceptor = proc;
}

/* 
 * check_timers()
 *	internal routine to see if any timers have sprung
 */
static void
check_timers (service_context sc)
{
    struct timespec right_now, tdiff;
    timerid tid;

    if (sc->ntimers) {
	/*
	 * check to see if any sprung, they're sorted so check the 
	 * zeroth, if it went off call the callback and resort. Then
	 * check the new zeroth....repeat until the zeroth is in the future.
	 *
         * zero out the timerid in the context and invoke the timercb
         * with a copy. This prevents an overzealous application who
         * does srv_rem_timeout() for this timer inside the timercb
         * from screwing things up. Leave the time alone though in
         * case the timercb ends up doing another qsort of the timers,
         * we still want this one to be the 0th when the timercb returns.
         *
         * Don't recalculate "right_now" after dispatching an event
         * because we want to ensure that timers added in a callback
         * have to go through select() before being dispatched, that
         * way we don't starve our file descriptors.
	 */
        clock_gettime(CLOCK_MONOTONIC, &right_now);
        tdiff = sc->timers[0].to;
        while (cmp_time(&tdiff, &right_now) < 1) {
            tid = sc->timers[0].id;
            sc->timers[0].id = 0;
            (*sc->timers[0].proc)(tid, sc->timers[0].data);
            sc->timers[0].to.tv_sec = sc->timers[0].to.tv_nsec = 0;
            qsort(sc->timers, sc->ntimers, sizeof(struct timer),
                  (int (*)())cmp_timers);
            sc->ntimers--;
            tdiff = sc->timers[0].to;
        }
	/*
	 * if there's any left the zero'th timer is the one that'll go off next
	 */
	if (sc->ntimers > 0) {
	    tdiff = sc->timers[0].to;
	    sub_time(&tdiff, &right_now);
	    sc->gbl_timer = tdiff;
	} else {
	    sc->gbl_timer.tv_sec = 1000;
	    sc->gbl_timer.tv_nsec = 0;
	}
    } else {
	sc->gbl_timer.tv_sec = 1000;
	sc->gbl_timer.tv_nsec = 0;
    }
    return;
}

/*
 * srv_main_loop()
 *	sit back, relax, let the service context do the work for you
 */
int
srv_main_loop(service_context sc)
{
    fd_set rfds, wfds, efds;
    int i, active;
    struct timeval timeval;

    while (sc->keep_running) {
	/*
	 * first check whether any timers expired while we were doing other things
	 */
	check_timers(sc);
	memcpy((char *)&rfds, (char *)&sc->readfds, sizeof(fd_set));
	memcpy((char *)&wfds, (char *)&sc->writefds, sizeof(fd_set));
        memcpy((char *)&efds, (char *)&sc->exceptfds, sizeof(fd_set));
	/*
	 * then wait for either inputs or the next scheduled timer to go off
	 */
	timespec_to_timeval(&sc->gbl_timer, &timeval);
	if (sc->ninputs || sc->noutputs) {
	    active = select(NFDS, &rfds, &wfds, &efds, &timeval);
	} else {
	    active = select(0, NULL, NULL, NULL, &timeval);
	}
	/*
	 * if an fd is set then process...
         *
         * for the same reason that you should let people off the elevator before
         * you try to get on the elevator (it's not only etiquette!) check the
         * outputs before the inputs.
	 */
	if (active > 0) {
	    for (i=0; i<sc->noutputs; i++) {
		if (FD_ISSET(sc->outputs[i].fd, &wfds)) {
		    (*sc->outputs[i].proc)(sc->outputs[i].fd, sc->outputs[i].data);
		    FD_CLR(sc->outputs[i].fd, &wfds);
		}
	    }
	    for (i=0; i<sc->ninputs; i++) {
                if (FD_ISSET(sc->inputs[i].fd, &efds)) {
                    /*
                     * we could just remove the problematic socket from
                     * the service context in here but it just doesn't
                     * seem right to mask such an error. Invoke the exceptor,
                     * if defined, orjust exit.
                     */
                    if (sc->exceptor == NULL) {
                        return sc->inputs[i].fd;
                    } else {
                        (*sc->exceptor)(sc->inputs[i].fd, NULL);
                    }
                    continue;
                }
		if (FD_ISSET(sc->inputs[i].fd, &rfds)) {
		    (*sc->inputs[i].proc)(sc->inputs[i].fd, sc->inputs[i].data);
		    FD_CLR(sc->inputs[i].fd, &rfds);
		}
	    }
	} else if ((active < 0) && (errno != EINTR)) {
	    /*
	     * if active < 0 and errno is EINTR we caught a signal
	     * so just go back and enter select, otherwise there's
	     * some error-- e.g. bad fd-- so return -1.
	     */
	    return -1;
	}
	/*
	 * if active = 0 then the timer fired, go through the loop and handle
	 * this condition in check_timers()
	 */
    }

    return 0;
}

/*
 * srv_create_context()
 *	create a service context
 */
service_context
srv_create_context(void)
{
    service_context blah;

    if ((blah = (service_context)malloc(sizeof(struct _servcxt))) == NULL) {
        sae_debug(SAE_DEBUG_ERR, "context was NULL\n");
        return NULL;
    }
    blah->timer_id = 0;
    FD_ZERO(&blah->readfds);
    FD_ZERO(&blah->writefds);
    FD_ZERO(&blah->exceptfds);
    bzero((char *)blah->timers, (NTIMERS * sizeof(struct timer)));
    bzero((char *)blah->inputs, (NFDS * sizeof(struct source)));
    bzero((char *)blah->outputs, (NFDS * sizeof(struct source)));
    blah->ntimers = blah->ninputs = blah->noutputs = 0;
    blah->gbl_timer.tv_sec = 1000;
    blah->gbl_timer.tv_nsec = 0;
    blah->exceptor = NULL;
    blah->keep_running = 1;

    return blah;
}

/*
 * srv_cancel_main_loop()
 *	Exit the main loop in srv_main_loop()
 *	at the earliest opportunity; It can be
 *	called from within signal handler
 *	context
 */
void
srv_cancel_main_loop(service_context context)
{
	context->keep_running = 0;
}
