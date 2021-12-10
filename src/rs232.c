/***********************************************************************
*
* rs232.c
*
* Linux tty interface.
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

#include "rs232.h"
#include "config.h"

#include <stdlib.h>
#include <errno.h>
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

BOOL Rs232SetRts(BOOL State );
BOOL Rs232SetDtr(BOOL State );

int comport;

struct termios new_port_settings,
               old_port_settings;

unsigned int rs232_timeout_ms;
BOOL rs232_debug = FALSE;

int Rs232TranslateBaudrate (int baudrate)
{
    int baudr;
    switch(baudrate)
    {
        case      50 : baudr = B50;
                       break;
        case      75 : baudr = B75;
                       break;
        case     110 : baudr = B110;
                       break;
        case     134 : baudr = B134;
                       break;
        case     150 : baudr = B150;
                       break;
        case     200 : baudr = B200;
                       break;
        case     300 : baudr = B300;
                       break;
        case     600 : baudr = B600;
                       break;
        case    1200 : baudr = B1200;
                       break;
        case    1800 : baudr = B1800;
                       break;
        case    2400 : baudr = B2400;
                       break;
        case    4800 : baudr = B4800;
                       break;
        case    9600 : baudr = B9600;
                       break;
        case   19200 : baudr = B19200;
                       break;
        case   38400 : baudr = B38400;
                       break;
        case   57600 : baudr = B57600;
                       break;
        case  115200 : baudr = B115200;
                       break;
        case  230400 : baudr = B230400;
                       break;
        case  460800 : baudr = B460800;
                       break;
        case  500000 : baudr = B500000;
                       break;
        case  576000 : baudr = B576000;
                       break;
        case  921600 : baudr = B921600;
                       break;
        case 1000000 : baudr = B1000000;
                       break;
        default      : printf("invalid baudrate\n");
                       return FALSE;
                       break;
    }
    return baudr;
}

int Rs232GetFd( void )
{
    return comport;
}

BOOL Rs232Open( char *comport_name, unsigned int baudrate )
{
    int baudr;

    baudr = Rs232TranslateBaudrate(baudrate);

    comport = open(comport_name, O_RDWR | O_NOCTTY | O_NDELAY | O_NONBLOCK);

    if(comport==-1)
    {
        syslog(LOG_ERR,"rs232: unable to open com-port: errno:%d %m", errno);
        return FALSE;
    }

    if(tcgetattr(comport, &old_port_settings))
    {
        close(comport);
        syslog(LOG_ERR,"rs232: unable to get port settings");
        return FALSE;
    }

    memset(&new_port_settings, 0, sizeof(new_port_settings));

    tcgetattr(comport, &new_port_settings);
    new_port_settings.c_cflag = baudr | CS8 | CLOCAL | CREAD | CRTSCTS;
    new_port_settings.c_iflag = IGNPAR;
    new_port_settings.c_oflag = 0;
    new_port_settings.c_lflag = 0;
    new_port_settings.c_cc[VMIN] = 0;      // block untill n bytes are received
    new_port_settings.c_cc[VTIME] = 0;     // block untill a timer expires (n * 100 mSec.)
    if(tcsetattr(comport, TCSANOW, &new_port_settings))
    {
        close(comport);
        syslog(LOG_ERR,"rs232: unable to set port settings");
        return FALSE;
    }

    /* flush input and output */
    Rs232RxPurge();
    Rs232TxPurge();


    /* set signal */
    Rs232SetRts(TRUE);
    Rs232SetDtr(TRUE);

    return TRUE;
}

void Rs232Close( void )
{
    /* flush i/o buffers */
    Rs232TxPurge();
    Rs232RxPurge();

    /* set signal */
    Rs232SetRts(FALSE);
    Rs232SetDtr(FALSE);

    /* TEMP*/
    /* Force speed to 0 baud to set DTR down */
    cfsetspeed(&old_port_settings, B0);
    /* Bring RTS down (to force autobauding ?) */
    old_port_settings.c_cflag &= ~CRTSCTS;

    /* Restore old settings */
    if (tcsetattr(comport, TCSANOW, &old_port_settings) == 1)
    {
        syslog(LOG_ERR,"rs232: unable to restore old settings");
    }

    sleep(1);

    if(close(comport) == -1)
    {
        syslog(LOG_ERR,"rs232: unable to close port");
    }
}

void Rs232DebugEnable( BOOL flag )
{
    rs232_debug = flag;
}

int Rs232ReadData( char *buf, unsigned int size)
{
    /* Set timeout */
    struct timeval timeout;
    timeout.tv_sec = rs232_timeout_ms/1000;
    timeout.tv_usec = rs232_timeout_ms%1000;

    /* Initialize file descriptor sets */
    fd_set read_fds, write_fds, except_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    FD_ZERO(&except_fds);
    FD_SET(comport, &read_fds);

    int i = 0, n = 0;
    while (i < size) {
        /* Wait for input to become ready or until the time out; the first parameter is
         * 1 more than the largest file descriptor in any of the sets
         * */
        if (select(comport + 1, &read_fds, &write_fds, &except_fds, &timeout) == 1) {
            n = read(comport, &buf[i], size - i);
            if (n <= 0)
            {
                printf("<-read_error\n");
                return  -1;
            }
            i += n;
#ifdef DEBUGGING_ENABLED

            if(rs232_debug)
            {
                char *tt = calloc(1, n+1);
                memcpy(tt, buf, n);
                printf("<- n:%d [", n);
                int j;
                for (j=0;j<n;j++)
                {
                    printf("%.2X ", (unsigned int)tt[j]);
                }
                printf("]\n");
                free(tt);
            }
#endif
        }
        else
        {
#ifdef DEBUGGING_ENABLED
            if(rs232_debug)
            {
                printf("<-timeout\n");
            }
#endif
            return -2;
        }
    }
    return 0;
}

int Rs232ReadData2( char *buf, unsigned int size)
{
    int n = read(comport, &buf[0], size);
#ifdef DEBUGGING_ENABLED
    if(rs232_debug)
    {
        if (n > 0) {
            char *tt = calloc(1, n+1);
            memcpy(tt, &buf[0], n);
            printf("< [%s] (0x%x) n:%d\n", tt, (unsigned int)tt[0],n);
            free(tt);
        }
    }
#endif
    return n;
}

BOOL Rs232WriteData(const char * buf, int size )
{
#ifdef DEBUGGING_ENABLED
    if(rs232_debug)
    {
        if (size > 0) {
            char *tt = calloc(1, size+1);
            memcpy(tt, &buf[0], size);
            printf("> [%s] (0x%x) n:%d\n", tt, (unsigned int)tt[0],size);
            free(tt);
        }
    }
#endif
    return (write(comport, buf, size) > 0);
}

BOOL Rs232ChangeBaud( unsigned int BaudRate )
{
    int baudr = Rs232TranslateBaudrate(BaudRate);

    /* TODO: the port must be opened */

    new_port_settings.c_cflag = baudr | CS8 | CLOCAL | CREAD;
    if(tcsetattr(comport, TCSANOW, &new_port_settings))
    {
        Rs232Close();
        syslog(LOG_ERR,"rs232: unable to adjust the baudrate");
        return FALSE;
    }
    Rs232RxPurge();
    return TRUE;
}

void Rs232RxPurge( void )
{
    tcflush(comport, TCIFLUSH);
}

void Rs232TxPurge( void )
{
    tcflush(comport, TCOFLUSH);
}


void Rs232SetReadTimeout(unsigned int ms)
{
    /* the port must be opened */
    /*new_port_settings.c_cc[VTIME] = ms/10;
    if(tcsetattr(comport, TCSANOW, &new_port_settings))
    {
        close(comport);
        syslog(LOG_ERR,"unable to adjust read timeout");
        return FALSE;
    }*/
    rs232_timeout_ms = ms;
}

BOOL Rs232GetCts(BOOL * pCtsState )
{
    int status;

    ioctl(comport, TIOCMGET, &status);

    return ((status&TIOCM_CTS) == *pCtsState);
}

BOOL Rs232GetDsr(BOOL * pDsrState )
{
    int status;

    ioctl(comport, TIOCMGET, &status);

    return ((status&TIOCM_CTS) == *pDsrState);
}

BOOL Rs232SetDtr(BOOL State )
{
    int status;

    if(ioctl(comport, TIOCMGET, &status) == -1)
    {
        syslog(LOG_ERR,"rs232: unable to get portstatus 3");
    }

    if(State)
        status |= TIOCM_DTR;    /* turn on DTR */
    else
        status &= ~TIOCM_DTR;    /* turn off DTR */

    if(ioctl(comport, TIOCMSET, &status) == -1)
    {
        syslog(LOG_ERR,"rs232: unable to set portstatus 3");
        return FALSE;
    }
    return TRUE;
}

BOOL Rs232SetRts(BOOL State )
{
    int status;

    if(ioctl(comport, TIOCMGET, &status) == -1)
    {
        syslog(LOG_ERR,"rs232: unable to get portstatus 4");
    }

    if(State)
        status |= TIOCM_RTS;    /* turn on RTS */
    else
        status &= ~TIOCM_RTS;    /* turn off RTS */

    if(ioctl(comport, TIOCMSET, &status) == -1)
    {
        syslog(LOG_ERR,"rs232: unable to set portstatus 4");
        return FALSE;
    }
    return TRUE;
}

