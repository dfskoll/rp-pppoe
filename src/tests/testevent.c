/***********************************************************************
*
* testevent.c
*
* Test event-handling code.
*
* Copyright (C) 2001 by Roaring Penguin Software Inc.
* Copyright (C) 2018-2023 Dianne Skoll
*
***********************************************************************/

#include <sys/time.h>
#include <unistd.h>

#include "event.h"
#include <stdio.h>
#include <time.h>

void
timerCallback(EventSelector *es,
	      int fd, unsigned int flags, void *data)
{
    time_t now;
    struct timeval interval;

    time(&now);

    interval.tv_sec = 1;
    interval.tv_usec = 0;

    printf("Timer callback called!\n");
    printf("Time is %s", ctime(&now));
    printf("fd=%d, flags=%u, data=%p\n\n", fd, flags, data);

    Event_AddTimerHandler(es, interval, timerCallback, NULL);
}

int
main()
{
    struct timeval interval;
    EventSelector *es = Event_CreateSelector();

    interval.tv_sec = 1;
    interval.tv_usec = 0;
    Event_AddTimerHandler(es, interval, timerCallback, NULL);

    while(1) {
	Event_HandleEvent(es);
    }
}

