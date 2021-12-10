/***********************************************************************
*
* modem.c
*
* Wrapper over raw Rs232 interface.
*
* Copyright (C) 2014 by Savoir Faire Linux.
*
* This program may be distributed according to the terms of the GNU
* General Public License, version 2 or (at your option) any later version.
*
* $Id$
*
* LIC: GPL
*
***********************************************************************/

#include "config.h"
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "pppoe.h"
#include "modem.h"
#include "rs232.h"

static BOOL modemSendCmd(const char *cmd, const char *str, int retries);
static char * modemExpectStr(const char * str, int n_line_max);
static char *com_port = NULL;
static int baudrate;
static BOOL modem_debug = FALSE;
static char input_buffer[256];

BOOL modemInit(char *Port, int Baudrate)
{
    BOOL res = TRUE;

    if (com_port) {
	free(com_port);
    }
    com_port = strDup(Port);
    baudrate = Baudrate;
    Rs232SetReadTimeout(1000);

    modem_is_busy = FALSE;

    if(!modemOpen())
        res = FALSE;

    if(res && !modemHangup())
        res = FALSE;

    if (res && !modemSendCmd("ATE0\r", "OK", 30))
        res = FALSE;

    syslog(LOG_INFO,"Modem: initialized=%s\n",res? "OK":"FAIL");

    modemClose();
    return TRUE;
}

int
modemGetFd( void )
{
    return Rs232GetFd();
}

BOOL modemOpen( void )
{
    if( FALSE == Rs232Open( com_port, baudrate ) )
    {
        syslog(LOG_ERR,"Modem: can't open port %s at baudrate %d", com_port, baudrate ) ;
        return FALSE;
    }
    syslog(LOG_INFO,"Modem: opened\n");
    return TRUE;
}

void modemClose( void )
{
    Rs232Close();
    syslog(LOG_INFO,"Modem: closed\n");
}

void modemDebugEnable( BOOL flag )
{
    modem_debug = flag;
    Rs232DebugEnable(flag);
}

BOOL modemDial(char *num)
{
    BOOL res = TRUE;
    char Command[128] = "atdt";

    if (strlen(num) > 128-1-5) {
	syslog(LOG_ERR, "Number too long: %s", num);
	return FALSE;
    }

    strcat(Command, num);
    strcat(Command, "\r");

    if (modem_is_busy)
        return FALSE;
    modem_is_busy = TRUE;

#ifdef DEBUGGING_ENABLED
    syslog(LOG_INFO,"Modem: > %s\n", Command);
#endif

    if(res && !modemSendCmd(Command, "ONNECT", 30))
        res = FALSE;

    syslog(LOG_INFO, "Modem: dialup=%s", (res)? "OK" : "FAIL");

    if (res)
    {
        Rs232RxPurge();
        Rs232SetReadTimeout(10);
    }
    return res;
}

BOOL modemHangup()
{
    BOOL res = TRUE;
    modem_is_busy = FALSE;

    Rs232RxPurge();
    Rs232SetReadTimeout(1000);

    /* ignore result cause the modem may already be in cmd mode */
    modemSendCmd("+++", "OK", 6);

    if(res && !modemSendCmd("ATH0\r", "OK", 20))
        res = FALSE;

    syslog(LOG_INFO,"Modem: hangup=%s", res?"OK":"FAIL");
    return res;
}

BOOL modemSendCmd(const char *cmd, const char *str, int retries)
{
    Rs232WriteData(cmd, strlen(cmd));
    return (modemExpectStr(str, retries) != NULL);
}

int modemSignalStrength( void )
{
    char Command[7] = "at+csq\r";
    int i;
    char *c;
    char line[256];
    char csq[2];


#ifdef DEBUGGING_ENABLED
    syslog(LOG_INFO,"Modem: > %s", Command);
#endif
    Rs232WriteData(Command, strlen(Command));

    for(i=0; i<30; i++)
    {
        line[0] = '\0';
        if(Rs232ReadData(line, 255))
        {
            c = strstr(line, "CSQ");
            if(c)
            {
                c = strstr(line, ":");
                if((c) && (c[1]))
                {
                    csq[0] = c[1];
                    csq[1] = '\0';
                    syslog(LOG_INFO, "Modem: < csq=%s", csq);
                    return atoi(csq);
                }
            }
        }
    }
    return 0;
}


static char * modemExpectStr(const char * str, int n_line_max)
{
    int i=0;
    char *c;

    c = strstr(input_buffer, str);
    if(c)
    {
#ifdef DEBUGGING_ENABLED
        if(modem_debug)
            syslog(LOG_INFO, "Modem: < expected [try:%d]: %s", i, str);
#endif
        return c;
    }

    for(i=1; i<n_line_max; i++)
    {
        input_buffer[0] = '\0';
        if(Rs232ReadData(input_buffer, 255))
        {
            c = strstr(input_buffer, str);
            if(c)
            {
#ifdef DEBUGGING_ENABLED
            if(modem_debug)
                syslog(LOG_INFO, "modem < expected [try:%d]: %s", i, str);
#endif
                return c;
            }
            else if (strstr(input_buffer, "CARRIER"))
            {
                syslog(LOG_ERR, "modem < interrupt signal: NO CARRIER");
                return NULL;
            }
            else if (strstr(input_buffer, "ERROR")) /*  TODO??? BUSY NO DIALTONE VOICE */
            {
                syslog(LOG_ERR, "modem < interrupt signal: ERROR");
                return NULL;
            }
#ifdef DEBUGGING_ENABLED
            if(modem_debug)
                syslog(LOG_INFO, "modem < [%d]: %s", i, input_buffer);
#endif
        }
    }
#ifdef DEBUGGING_ENABLED
    if(modem_debug)
        syslog(LOG_INFO, "modem < timeout");
#endif
    return NULL;
}

BOOL modemWriteBuf( char *str, int len)
{
#ifdef DEBUGGING_ENABLED
    if(modem_debug)
    {
        char tx_buf [256];
        snprintf(tx_buf, (len<256)? len : 255, "%s", str);
        syslog(LOG_INFO,"Modem: > [%d] %s", len, tx_buf);
    }
#endif
    Rs232WriteData(str, len);
    return TRUE;
}

int modemReadBuf( char *Response, int MaxChars)
{
    int pos = Rs232ReadData2(Response, MaxChars);

#ifdef DEBUGGING_ENABLED
    if(modem_debug)
    {
        char res[256];
        snprintf(res, (pos<256)? pos : 255, "%s", Response);
        syslog(LOG_INFO,"Modem: < [%d] %s", pos, res);
    }
#endif
    return pos;
}
