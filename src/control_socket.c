/***********************************************************************
*
* control_socket.c
*
* Re-usable code for implementing a control socket.
*
* Copyright (C) 2000-2012 Roaring Penguin Software Inc.
* Copyright (C) 2018-2023 Dianne Skoll
* Copyright (C) 2022 Jaco Kroon
*
* This program may be distributed according to the terms of the GNU
* General Public License, version 2 or (at your option) any later version.
*
* $Id$
*
* SPDX-License-Identifier: GPL-2.0-or-later
*
***********************************************************************/
#define _GNU_SOURCE

#include "control_socket.h"
#include "event_tcp.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <stdbool.h>
#include "pppoe.h"

#define MAX_CMD_LEN	2048

typedef struct ClientContext {
    ControlCommand *commands;
    void* clientpvt;
    control_socket_exit_handler exithandler;
} ClientContext;

typedef struct ClientConnection {
    int fd;
    ClientContext *context;
    int ctxi;

    char *writebuf;
    int writebuflen;

    bool close_on_write_complete;
} ClientConnection;

int control_socket_handle_command(ClientConnection *client, const char* const* argv, int argi,
                                  void *_subs, void *unused __attribute__((unused)))
{
    ControlCommand* subs = _subs;
    ControlCommand* selected = NULL;
    ControlCommand *cc;
    size_t wlen = 0;
    bool listall = true;
    if (argv[argi]) {
	wlen = strlen(argv[argi]);

	for (cc = subs; cc->command; ++cc) {
	    if (strncmp(cc->command, argv[argi], wlen) == 0) {
		/* the word starts with the provided input */
		/* if we previously found a match, it means the command is
		 * ambiguous, so drop-through and output list of available next
		 * options */
		if (selected) {
		    selected = NULL;
		    listall = false;
		    break;
		}
		selected = cc;
	    }
	}

	if (selected) {
	    return selected->handler(client, argv, argi+1, selected->pvt, client->context[client->ctxi].clientpvt);
	}
	cs_ret_printf(client, "%s '%s' not found or ambiguous, possible options:\n",
		argi ? "Sub-command" : "Command", argv[argi]);
    } else if (argi) {
        int i;
	cs_ret_printf(client, "Incomplete command after '");
	for (i = 0; i < argi; ++i) {
	    cs_ret_printf(client, "%s%s", i ? " " : "", argv[i]);
	}
	cs_ret_printf(client, "', possible completions:\n");
    } else {
	cs_ret_printf(client, "No command specified, base commands:\n");
    }
    for (cc = subs; cc->command; ++cc) {
	if (!listall && argv[argi] && strncmp(argv[argi], cc->command, wlen) != 0)
	    continue;
	cs_ret_printf(client, "  %s\n", cc->command);
    }
    cs_ret_printf(client, "-- end --\n");
    return 0;
}

void control_socket_cleanup_client(ClientConnection *client, int fd)
{
    int i;
    printErr("Closing UNIX control connection.");
    close(fd);
    for (i = client->ctxi; i >= 0; --i) {
	if (client->context[i].exithandler)
	    client->context[i].exithandler(client, client->context[i].clientpvt);
    }
    free(client->writebuf);
    free(client->context);
    free(client);
}

int control_socket_push_context(ClientConnection *client,
	control_socket_exit_handler exitfunc, ControlCommand* newroot, void* clientpvt)
{
  ClientContext *t = realloc(client->context, (client->ctxi + 2) * sizeof(*client->context));
    if (!t) {
	printErr("Memory allocation error trying to push UNIX control context.");
	return -1;
    }

    client->context = t;
    client->ctxi++;
    client->context[client->ctxi].commands = newroot;
    client->context[client->ctxi].exithandler = exitfunc;
    client->context[client->ctxi].clientpvt = clientpvt;
    return 0;
}

static void control_socket_read(EventSelector *es,
	int fd, char* command, int len, int flag, void *_client);

static
void control_socket_write_complete(EventSelector *es, int fd, char* buf,
	int len, int flag, void *_client)
{
    ClientConnection *client = _client;

    /* free_state takes care of freeing buf */
    if (flag == EVENT_TCP_FLAG_COMPLETE &&
	    !client->close_on_write_complete &&
	    EventTcp_ReadBuf(es, fd, MAX_CMD_LEN, '\n', control_socket_read, -1, _client))
	return;

    if (flag != EVENT_TCP_FLAG_COMPLETE)
	printErr("Error writing to control socket");
    control_socket_cleanup_client(client, fd);
}

static
void control_socket_read(EventSelector *es,
	int fd, char* command, int len, int flag, void *_client)
{
    char *argv[128];
    int argi = 0;
    ClientConnection *client = _client;

    if (flag != EVENT_TCP_FLAG_COMPLETE)
	goto closeout;

    if (client->writebuf) {
	printErr("BUG, we're not supposed to have a pre-existing write-buffer.  Contents:\n%.*s---",
			client->writebuflen, client->writebuf);
	goto closeout;
    }

    command[len-1] = 0; /* \n => 0 */
    if (strcmp(command, "quit") == 0 || (strcmp(command, "exit") == 0 && client->ctxi == 0)) {
	cs_printf(client, "Good bye.\n");
	client->close_on_write_complete = true;
	goto checkwrite;
    }

    if (strcmp(command, "exit") == 0) {
	if (client->context[client->ctxi].exithandler)
	    client->context[client->ctxi].exithandler(client, client->context[client->ctxi].clientpvt);
	client->ctxi--;
    }

    printErr("Received Control Command: %.*s.", len, command);

    while (*command) {
	int quoted;
	/* strip leading whitespace. */
	while (*command && isspace(*command))
	    ++command;
	/* break on EOL */
	if (!*command)
	    break;

	argv[argi] = command;
	/* find the end of the word. */
	quoted = *command++ == '"';
	while (*command && (
		    quoted ? (*command != '"' || command[-1] == '\\') : !isspace(*command)))
	    command++;

	if (quoted) {
	    if (*command != '"') {
		cs_printf(client, "Error locating closing quote for %s\n", argv[argi]);
		goto checkwrite;
	    }
	    if (command[1] && !isspace(command[1])) {
		cs_printf(client, "Unescaped mid-word quote in %s\n", argv[argi]);
		goto checkwrite;
	    }
	    argv[argi]++;
	}

	if (*command)
	    *command++ = 0;

	if (quoted) {
	    /* compress \" to ". */
	    char *s, *d;
	    s = d = strstr(argv[argi], "\\\"");
	    while (s && *s) {
		if (*s == '\\' && s[1] == '"')
		    ++s;
		*d++ = *s++;
	    }
	    *d = 0;
	}

	argi++;
    }
    argv[argi] = NULL;

    if (control_socket_handle_command(client, (const char*const*)argv, 0, client->context[0].commands, NULL) < 0)
	goto closeout;

checkwrite:
    if (client->writebuf) {
	if (!EventTcp_WriteBuf(es, fd, client->writebuf, client->writebuflen,
		    control_socket_write_complete, -1, client)) {
	    printErr("Failed to set up write buffer.  Closing control connection.");
	    goto closeout;
	}
	free(client->writebuf);
	client->writebuf = NULL;
	client->writebuflen = 0;
    } else {
	// no output, go directly to read mode again
	if (!EventTcp_ReadBuf(es, fd, MAX_CMD_LEN, '\n', control_socket_read, -1, client)) {
	    printErr("Failed to set up reader, closing control connection.");
	    goto closeout;
	}
    }

    return;
closeout:
    control_socket_cleanup_client(client, fd);

}

static
void control_socket_acceptor(EventSelector *es, int fd, void* _root)
{
    printErr("Accepted UNIX control connection.");
    ControlCommand *root = _root;
    ClientConnection *client = malloc(sizeof(*client));
    if (!client) {
	printErr("Error allocating memory for new client.");
	goto errout;
    }
    memset(client, 0, sizeof(*client));
    client->context = malloc(sizeof(*client->context));
    if (!client->context) {
	printErr("Error allocating memory for new client.");
	goto errout;
    }
    memset(&client->context[0], 0, sizeof(client->context[0]));
    client->context[0].commands = root;

    if (!EventTcp_ReadBuf(es, fd, MAX_CMD_LEN, '\n', control_socket_read, -1, client)) {
	printErr("Failed to set up reader, closing control connection.");
	goto errout;
    }
    return;

errout:
    close(fd);
    if (client) {
	if (client->context)
	    free(client->context);
	free(client);
    }
}

int control_socket_init(EventSelector *event_selector, const char* unix_socket, ControlCommand* root)
{
    struct sockaddr_un su;
    int unix_fd = -1;
    mode_t oldmask;

    su.sun_family = AF_UNIX;
    if (sizeof(su.sun_path) - 1 < strlen(unix_socket)) {
	printErr("Error creating UNIX socket: %s.",
		"Specified path too long to fit in socket address structure");
	goto failout;
    }
    strcpy(su.sun_path, unix_socket);

    unix_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (unix_fd < 0) {
	printErr("Error creating UNIX socket: %s.",
		strerror(errno));
	goto failout;
    }

    fcntl(unix_fd, F_SETFL, fcntl(unix_fd, F_GETFL, 0) | FD_CLOEXEC);

    /* I don't like this but in case of left-over sockets we have no choice. */
    unlink(unix_socket);

    oldmask = umask(0177);
    if (bind(unix_fd, (struct sockaddr *)&su, sizeof(su)) < 0) {
	umask(oldmask);
	printErr("Error binding UNIX socket: %s.",
		strerror(errno));
	goto failout;
    }
    umask(oldmask);

    if (listen(unix_fd, 8) < 0) {
	printErr("Error listening on UNIX socket: %s.",
		strerror(errno));
	goto failout;
    }

    if (!EventTcp_CreateAcceptor(event_selector, unix_fd, control_socket_acceptor, root)) {
	printErr("Error creating UNIX socket acceptor event handler.");
	goto failout;
    }

    return 0;
failout:
    if (unix_fd >= 0)
	close(unix_fd);
    return -1;
}

int control_socket_printf(ClientConnection *client, const char* fmt, ...)
{
    char *bfr;
    va_list vargs;

    va_start(vargs, fmt);
    int l = vasprintf(&bfr, fmt, vargs);
    va_end(vargs);
    if (l < 0)
	return -1;

    void* tmp = realloc(client->writebuf, client->writebuflen + l);
    if (!tmp)
	return -1;
    memcpy(tmp + client->writebuflen, bfr, l);
    free(bfr);
    client->writebuf = tmp;
    client->writebuflen += l;
    return 0;
}
