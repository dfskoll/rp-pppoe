
#if !defined( __RS232_H_INCLUDED__ )
#define __RS232_H_INCLUDED__

#include <stdio.h>
#include <string.h>

#include <termios.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include "types.h"



typedef void (* t_rs232_rx_notify)(int Port) ;

BOOL Rs232Open( char * comport_name, unsigned int BaudRate  ) ;
void Rs232Close( void ) ;
void Rs232DebugEnable( BOOL flag );
BOOL Rs232ChangeBaud( unsigned int BaudRate ) ;
void Rs232SetReadTimeout( unsigned int Milliseconds )  ;
BOOL Rs232WriteData( const char * pData, int Len ) ;
int Rs232ReadData( char * pBuff,unsigned int Len ) ;
int Rs232ReadData2( char * pBuff,unsigned int Len ) ;
void Rs232RxPurge( void ) ;
void Rs232TxPurge( void ) ;
BOOL Rs232GetCts( BOOL * pState ) ;
BOOL Rs232SetDtr( BOOL State ) ;
int Rs232GetFd( void );

#endif /* !defined( __RS232_H_INCLUDED__ ) */
