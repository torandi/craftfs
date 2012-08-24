#include <stdio.h>
#include <stdlib.h>
#include "timer.h"
/*
 * Starts the timer t
 */
void
timer::start(timer::timer_t &t) {
	gettimeofday(&t.start,NULL);
}

/*
 * Stops the timer t
 */
void
timer::stop(timer::timer_t &t) {
	gettimeofday(&t.stop,NULL);
}

/*
 * Returns the number of seconds the timer run (with much precision)
 */
float
timer::get(timer::timer_t &t) {
	return ((t.stop.tv_sec-t.start.tv_sec)*1000000.0 + (t.stop.tv_usec-t.start.tv_usec))/1000000.0;
}
