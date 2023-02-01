/**********************************************************************
*
* control_socket.h
*
* Definitions for the PPPoE server's control socket.
*
* Copyright (C) 2001-2012 Roaring Penguin Software Inc.
* Copyright (C) 2018-2022 Dianne Skoll
* Copyright (C) 2022 Jaco Kroon
*
* This program may be distributed according to the terms of the GNU
* General Public License, version 2 or (at your option) any later version.
*
* SPDX-License-Identifier: GPL-2.0-or-later
***********************************************************************/

#include "event.h"

typedef struct ClientConnection ClientConnection;

/* command control structures */
typedef struct ControlCommand {
    const char* command; /* single word such as 'set' */
    int (*handler)(struct ClientConnection* cc, const char * const * argv, int argi, void* cmdpvt, void* clientpvt); /* argv contains word-split command, argi the index that needs to be handled next, zero return indicates success, negative return states to close the socket, positive values indicates that there was a proccessing failure and further processing should stop, but the connection can be retained. fd is a file descriptor to the control socket. */
    void* pvt;
} ControlCommand;

typedef void (*control_socket_exit_handler)(struct ClientConnection *cc, void* clientpvt);

int control_socket_init(EventSelector *event_selector, const char* unix_socket,
	ControlCommand* root);
int control_socket_push_context(struct ClientConnection *cc,
	control_socket_exit_handler exitfunc, ControlCommand* newroot, void* clientpvt);
int control_socket_handle_command(struct ClientConnection *client, const char* const* argv, int argi,
	void* _subs, void*);

__attribute__ ((format (printf, 2, 3))) int control_socket_printf(struct ClientConnection *cc, const char* fmt, ...);
#define cs_printf(...) control_socket_printf(__VA_ARGS__)
#define cs_ret_printf(...) do { if (cs_printf(__VA_ARGS__) < 0) return -1; } while(0)
