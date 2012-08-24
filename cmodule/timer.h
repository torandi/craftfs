#ifndef _TIMER_H_
#define _TIMER_H_
#include <sys/time.h>

namespace timer {
	typedef struct {
		timeval start;
		timeval stop;
	} timer_t;

	//timer functions
	void start(timer_t &t);
	void stop(timer_t &t);
	float get(timer_t &t);
}
#endif
