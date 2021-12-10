

#if !defined( __MODEM_H_INCLUDED__ )
#define __MODEM_H_INCLUDED__

#include <unistd.h>
#include "types.h"

BOOL modemInit(char *Port, int Baudrate);
int modemGetFd( void );
BOOL modemOpen( void );
void modemClose( void );
void modemDebugEnable( BOOL flag );
BOOL modemDial(char *num);
BOOL modemHangup(void);
int modemSignalStrength( void );
int modemReadBuf( char *Response, int MaxChars);
BOOL modemWriteBuf(char *str, int len);

unsigned char modem_input_buffer[4096];
BOOL modem_is_busy;
#endif
