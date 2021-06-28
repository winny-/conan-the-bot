/*
 * Copyright (C) 2004-2009 Georgy Yunaev gyunaev@ulduzsoft.com
 *
 * This example is free, and not covered by LGPL license. There is no
 * restriction applied to their modification, redistribution, using and so on.
 * You can study them, modify them, use them in your own program - either
 * completely or partially. By using it you may give me some credits in your
 * program, but you don't have to.
 *
 *
 * This example tests most features of libirc. It can join the specific
 * channel, welcoming all the people there, and react on some messages -
 * 'help', 'quit', 'dcc chat', 'dcc send', 'ctcp'. Also it can reply to
 * CTCP requests, receive DCC files and accept DCC chats.
 *
 * Features used:
 * - nickname parsing;
 * - handling 'channel' event to track the messages;
 * - handling dcc and ctcp events;
 * - using internal ctcp rely procedure;
 * - generating channel messages;
 * - handling dcc send and dcc chat events;
 * - initiating dcc send and dcc chat.
 *
 * $Id: irctest.c 124 2013-11-28 05:44:10Z gyunaev $
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <error.h>

#include "libircclient.h"
#include "toml.h"

struct bot_config
{
	struct network_config **networks;
};

/*
 * The IRC Network configuration object.
 */
struct network_config
{
	char *host;
	unsigned short port;
	char *nick;
	char **channels;
	char ssl;
	char verify_ssl;
};

/*
 * We store data in IRC session context.
 */
typedef struct
{
	char 	* channel;
	char 	* nick;

} irc_ctx_t;


void addlog (const char * fmt, ...)
{
	FILE * fp;
	char buf[1024];
	va_list va_alist;

	va_start (va_alist, fmt);
	vsnprintf (buf, sizeof(buf), fmt, va_alist);
	va_end (va_alist);

	printf ("%s\n", buf);

	if ( (fp = fopen ("irctest.log", "ab")) != 0 )
	{
		fprintf (fp, "%s\n", buf);
		fclose (fp);
	}
}


void dump_event (irc_session_t * session, const char * event, const char * origin, const char ** params, unsigned int count)
{
	char buf[512];
	int cnt;

	buf[0] = '\0';

	for ( cnt = 0; cnt < count; cnt++ )
	{
		if ( cnt )
			strcat (buf, "|");

		strcat (buf, params[cnt]);
	}


	addlog ("Event \"%s\", origin: \"%s\", params: %d [%s]", event, origin ? origin : "NULL", cnt, buf);
}


void event_join (irc_session_t * session, const char * event, const char * origin, const char ** params, unsigned int count)
{
	dump_event (session, event, origin, params, count);
	irc_cmd_user_mode (session, "+i");
	irc_cmd_msg (session, params[0], "Hi all");
}


void event_connect (irc_session_t * session, const char * event, const char * origin, const char ** params, unsigned int count)
{
	irc_ctx_t * ctx = (irc_ctx_t *) irc_get_ctx (session);
	dump_event (session, event, origin, params, count);

	irc_cmd_join (session, ctx->channel, 0);
}


void event_privmsg (irc_session_t * session, const char * event, const char * origin, const char ** params, unsigned int count)
{
	dump_event (session, event, origin, params, count);

	printf ("'%s' said me (%s): %s\n",
		origin ? origin : "someone",
		params[0], params[1] );
}


void dcc_recv_callback (irc_session_t * session, irc_dcc_t id, int status, void * ctx, const char * data, unsigned int length)
{
	static int count = 1;
	char buf[12];

	switch (status)
	{
	case LIBIRC_ERR_CLOSED:
		printf ("DCC %d: chat closed\n", id);
		break;

	case 0:
		if ( !data )
		{
			printf ("DCC %d: chat connected\n", id);
			irc_dcc_msg	(session, id, "Hehe");
		}
		else
		{
			printf ("DCC %d: %s\n", id, data);
			sprintf (buf, "DCC [%d]: %d", id, count++);
			irc_dcc_msg	(session, id, buf);
		}
		break;

	default:
		printf ("DCC %d: error %s\n", id, irc_strerror(status));
		break;
	}
}


void dcc_file_recv_callback (irc_session_t * session, irc_dcc_t id, int status, void * ctx, const char * data, unsigned int length)
{
	if ( status == 0 && length == 0 )
	{
		printf ("File sent successfully\n");

		if ( ctx )
			fclose ((FILE*) ctx);
	}
	else if ( status )
	{
		printf ("File sent error: %d\n", status);

		if ( ctx )
			fclose ((FILE*) ctx);
	}
	else
	{
		if ( ctx )
			fwrite (data, 1, length, (FILE*) ctx);
		printf ("File sent progress: %d\n", length);
	}
}


void event_channel (irc_session_t * session, const char * event, const char * origin, const char ** params, unsigned int count)
{
	char nickbuf[128];

	if ( count != 2 )
		return;

	printf ("'%s' said in channel %s: %s\n",
		origin ? origin : "someone",
		params[0], params[1] );

	if ( !origin )
		return;

	irc_target_get_nick (origin, nickbuf, sizeof(nickbuf));

	if ( !strcmp (params[1], "quit") )
		irc_cmd_quit (session, "of course, Master!");

	if ( !strcmp (params[1], "help") )
	{
		irc_cmd_msg (session, params[0], "quit, help, dcc chat, dcc send, ctcp");
	}

	if ( !strcmp (params[1], "ctcp") )
	{
		irc_cmd_ctcp_request (session, nickbuf, "PING 223");
		irc_cmd_ctcp_request (session, nickbuf, "FINGER");
		irc_cmd_ctcp_request (session, nickbuf, "VERSION");
		irc_cmd_ctcp_request (session, nickbuf, "TIME");
	}

	if ( !strcmp (params[1], "dcc chat") )
	{
		irc_dcc_t dccid;
		irc_dcc_chat (session, 0, nickbuf, dcc_recv_callback, &dccid);
		printf ("DCC chat ID: %d\n", dccid);
	}

	if ( !strcmp (params[1], "dcc send") )
	{
		irc_dcc_t dccid;
		irc_dcc_sendfile (session, 0, nickbuf, "irctest.c", dcc_file_recv_callback, &dccid);
		printf ("DCC send ID: %d\n", dccid);
	}

	if ( !strcmp (params[1], "topic") )
		irc_cmd_topic (session, params[0], 0);
	else if ( strstr (params[1], "topic ") == params[1] )
		irc_cmd_topic (session, params[0], params[1] + 6);

	if ( strstr (params[1], "mode ") == params[1] )
		irc_cmd_channel_mode (session, params[0], params[1] + 5);

	if ( strstr (params[1], "nick ") == params[1] )
		irc_cmd_nick (session, params[1] + 5);

	if ( strstr (params[1], "whois ") == params[1] )
		irc_cmd_whois (session, params[1] + 5);
}


void irc_event_dcc_chat (irc_session_t * session, const char * nick, const char * addr, irc_dcc_t dccid)
{
	printf ("DCC chat [%d] requested from '%s' (%s)\n", dccid, nick, addr);

	irc_dcc_accept (session, dccid, 0, dcc_recv_callback);
}


void irc_event_dcc_send (irc_session_t * session, const char * nick, const char * addr, const char * filename, unsigned long size, irc_dcc_t dccid)
{
	FILE * fp;
	printf ("DCC send [%d] requested from '%s' (%s): %s (%lu bytes)\n", dccid, nick, addr, filename, size);

	if ( (fp = fopen ("file", "wb")) == 0 )
		abort();

	irc_dcc_accept (session, dccid, fp, dcc_file_recv_callback);
}

void event_numeric (irc_session_t * session, unsigned int event, const char * origin, const char ** params, unsigned int count)
{
	char buf[24];
	sprintf (buf, "%d", event);

	dump_event (session, buf, origin, params, count);
}

static void my_toml_error(const char *msg, const char *msg1)
{
    fprintf(stderr, "ERROR: %s%s\n", msg, msg1?msg1:"");
    exit(1);
}

char parse_toml(FILE *fp, struct bot_config **cfg)
{
	char errbuf[200];
	toml_table_t *root = toml_parse_file(fp, errbuf, sizeof(errbuf));
	if (!root) {
		my_toml_error("cannot parse - ", errbuf);
	}
	toml_array_t *nets = toml_array_in(root, "network");
	struct bot_config *bot_config = malloc(sizeof(struct bot_config));
	bot_config->networks = calloc(1, sizeof(struct network_config *));
	if (!nets) {
		my_toml_error("cannot parse - no [[network]]", "");
	}
	size_t net_count = 0;
	for (int i = 0; i < toml_array_nelem(nets) ; i++, net_count++) {
		toml_table_t *the_net = toml_table_at(nets, i);
		if (!the_net) {
			my_toml_error("cannot parse [networks] :/", "");
		}
		bot_config->networks = reallocarray(bot_config->networks, net_count + 2, sizeof(struct network_config *));
		struct network_config *netcfg = bot_config->networks[net_count] = malloc(sizeof(struct network_config));
		memset(bot_config->networks + net_count + 1, 0, sizeof(struct network_config *));
		toml_datum_t host = toml_string_in(the_net, "host");
		if (!host.ok) {
			my_toml_error("cannot parse network host", "");
		}
		netcfg->host = strdup(host.u.s);
		free(host.u.s);
		toml_datum_t port = toml_int_in(the_net, "port");
		if (!port.ok || port.u.i > 65535 || port.u.i < 0) {
			my_toml_error("cannot parse network port", "");
		}
		netcfg->port = (unsigned short)port.u.i;
		toml_datum_t ssl = toml_bool_in(the_net, "ssl");
		netcfg->ssl = ssl.ok && ssl.u.b;
		toml_array_t *channels = toml_array_in(the_net, "channels");
		size_t channel_len = toml_array_nelem(channels);
		netcfg->channels = calloc(channel_len + 1, sizeof(char **));
		for (size_t j = 0; j < channel_len; j++) {
			toml_datum_t the_channel = toml_string_at(channels, j);
			if (!the_channel.ok) {
				my_toml_error("cannot parse channel", "");
			}
			netcfg->channels[j] = strdup(the_channel.u.s);
			free(the_channel.u.s);
		}
		toml_datum_t nick = toml_string_in(the_net, "nick");
		if (!nick.ok) {
			my_toml_error("cannot parse nick", "");
		}
		netcfg->nick = strdup(nick.u.s);
		free(nick.u.s);
		toml_datum_t verify_ssl = toml_bool_in(the_net, "verify_ssl");
		netcfg->verify_ssl = verify_ssl.ok ? verify_ssl.u.b : 1;
	}
	*cfg = bot_config;
	return 0;
}


int main (int argc, char **argv)
{
	irc_callbacks_t	callbacks;
	irc_ctx_t ctx;
	irc_session_t * s;

	if ( argc != 2 )
	{
		printf ("Usage: %s <config.toml>\n", argv[0]);
		return 1;
	}

	FILE *fp = fopen(argv[1], "r");
	struct bot_config *cfg;
	parse_toml(fp, &cfg);

	memset (&callbacks, 0, sizeof(callbacks));

	callbacks.event_connect = event_connect;
	callbacks.event_join = event_join;
	callbacks.event_nick = dump_event;
	callbacks.event_quit = dump_event;
	callbacks.event_part = dump_event;
	callbacks.event_mode = dump_event;
	callbacks.event_topic = dump_event;
	callbacks.event_kick = dump_event;
	callbacks.event_channel = event_channel;
	callbacks.event_privmsg = event_privmsg;
	callbacks.event_notice = dump_event;
	callbacks.event_invite = dump_event;
	callbacks.event_umode = dump_event;
	callbacks.event_ctcp_rep = dump_event;
	callbacks.event_ctcp_action = dump_event;
	callbacks.event_unknown = dump_event;
	callbacks.event_numeric = event_numeric;

	callbacks.event_dcc_chat_req = irc_event_dcc_chat;
	callbacks.event_dcc_send_req = irc_event_dcc_send;

	s = irc_create_session (&callbacks);

	if ( !s )
	{
		printf ("Could not create session\n");
		return 1;
	}

	ctx.channel = cfg->networks[0]->channels[0];
	ctx.nick = cfg->networks[0]->nick;

	irc_set_ctx (s, &ctx);

	char *host = cfg->networks[0]->host;
	if (cfg->networks[0]->ssl) {
		host = malloc(strlen(host) + 2);
		sprintf(host, "#%s", cfg->networks[0]->host);
	}

	if (!cfg->networks[0]->verify_ssl) {
		irc_option_set( s, LIBIRC_OPTION_SSL_NO_VERIFY );
	}

	// Initiate the IRC server connection
	if ( irc_connect (s, host, cfg->networks[0]->port, 0, cfg->networks[0]->nick, 0, 0) )
	{
		printf ("Could not connect: %s\n", irc_strerror (irc_errno(s)));
		return 1;
	}

	// and run into forever loop, generating events
	if ( irc_run (s) )
	{
		printf ("Could not connect or I/O error: %s\n", irc_strerror (irc_errno(s)));
		return 1;
	}

	return 1;
}
