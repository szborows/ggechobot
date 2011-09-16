/*
	This file is part of gg_stilz_bot. gg_stilz_bot is free software: 
	you can redistribute it and/or modify it under the terms of the 
	GNU General Public License as published by the Free Software 
	Foundation, version 2.

	This program is distributed in the hope that it will be useful, 
	but WITHOUT ANY WARRANTY; without even the implied warranty of 
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
	General Public License for more details.

	You should have received a copy of the GNU General Public License 
	along with this program; if not, write to the Free Software Foundation,
	Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

	Written by: Slawomir `stilz` Zborowski
	Copyleft 2010-2050 ;-)
*/

#include <sys/time.h>
#include "mtrand.h"
#include "ggechobot.h"

void read_data (gg_header& header, char* data)
{
	if (GG_RECV_MSG80 == header.type)
	{
		printf ("GG_RECV_MSG80\n");
		gg_recv_msg80* msg = (gg_recv_msg80*)malloc(header.length);
		memcpy ((char*)msg, data, header.length);

		// We echo received message
		char* resp = (char*)malloc(strlen(msg->text+msg->offset_plain-sizeof(gg_recv_msg80))+1);
		memcpy (resp, msg->text+msg->offset_plain-sizeof(gg_recv_msg80), strlen(msg->text+msg->offset_plain-sizeof(gg_recv_msg80)));
		resp[strlen(msg->text+msg->offset_plain-sizeof(gg_recv_msg80))] = 0x0;
		gg_send_message (msg->sender, resp);
		free (resp);
		free (msg);
	}
	else
	{
		/* We don't handle another packets */
	}
}

void* gg_receive_loop (void* user_data)
{
	fd_set rfds;
	struct timeval tv;
	int retval;

	while (1)
	{
		FD_ZERO (&rfds);
		FD_SET (sock_fd, &rfds);
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		retval = select (sock_fd+1, &rfds, NULL, NULL, &tv);
		if (retval == -1)
		{
			printf ("select() error...\n");
			return NULL;
		}
		else if (retval)
		{
			gg_clear_header (&rheader);
			int res = recv (sock_fd, (char*)&rheader, sizeof (rheader), 0);
			if (EAGAIN != res && EWOULDBLOCK != res && res > 0)
			{
				char* buf = (char*)malloc(rheader.length);
				res = recv (sock_fd, buf, rheader.length, 0);
				if (EAGAIN != res && res > 0)
				{
					read_data (rheader, buf);
				}
				free (buf);
			}
		}
		else
		{ /* No data within 5 seconds */	
		}
	}
}

void* gg_pingpong_loop (void* user_data)
{
	gg_header header;
	header.type = GG_PING;
	header.length = 0;
	while (1)
	{
		sleep (2*60);
		if (0 > send (sock_fd, (char*)&header, sizeof(header), 0))
			printf ("send() error lol! [ping header]");
	}
}

void gg_send_message (int uin, char* html_message)
{
	struct gg_send_msg80 msg;
	msg.recipient = uin;
	time ((time_t *)&msg.seq);
	msg._class = 0x20;
	msg.offset_plain = 0x14;
	msg.offset_attributes = 0x01;
	char* plain_message = "";

	gg_clear_header (&header);
	header.type = GG_SEND_MSG80;
	header.length = sizeof (msg)+strlen (html_message) + strlen (plain_message)+1+1+1;

	char* buf = (char*)malloc(sizeof(header)+sizeof(msg)+strlen(html_message)+1+strlen(plain_message)+1);
	int i = 0;
	memcpy (buf, (char*)&header, sizeof(header));
	i += sizeof(header);
	memcpy (buf+i, (char*)&msg, sizeof(msg));
	i += sizeof(msg);
	memcpy (buf+i, html_message, strlen(html_message)+1);
	i += strlen(html_message)+1;
	memcpy (buf+i, plain_message, strlen(plain_message)+1);
	i += strlen(plain_message)+1;

	if (0 > send (sock_fd, buf, i, 0))
	{	printf ("send() error lol! [msg header]\n");
	}

	char xxx = 0x0;
	if (0 > send (sock_fd, &xxx, 1, 0))
	{	printf ("send() error lol! [plain message]");
	}
}

void gg_change_mood (int m, char* status_msg)
{
	struct gg_new_status80 mood;
	mood.status = status_msg ? GG_STATUS_BUSY_DESCR : GG_STATUS_BUSY;
	mood.flags = 0;
	mood.description_size = status_msg ? strlen (status_msg) : 0;

	gg_clear_header (&header);
	header.type = GG_NEW_STATUS80;
	header.length = sizeof (mood) + (status_msg ? strlen (status_msg) : 0);

	if (0 > send (sock_fd, (char *)&header, sizeof (header), 0))
	{	printf ("send() error lol! [mood header]\n");
	}

	if (0 > send (sock_fd, (char *)&mood, sizeof (mood), 0))
	{	printf ("send() error lol! [mood struct]\n");
	}

	if (	status_msg && 
			0 > send (sock_fd, status_msg, strlen (status_msg), 0))
	{	printf ("send() error lol! [status string]\n");
	}

	printf ("Status zostal zmieniony !\n");
}

void gg_get_list (void)
{
	gg_clear_header (&header);
	header.type = GG_LIST_EMPTY;
	header.length = 0;

	if (0 > send (sock_fd, (char *)&header, sizeof (header), 0))
	{	printf ("send() error lol! [list empty header]");
	}
}

void* gg_command_loop (void* user_data)
{
	bool quit = false;
	char buf[512];
	memset (buf, 0x0, sizeof (buf));
	gg_get_list();	

	while (!quit)
	{
		printf ("> ");

		gets (buf);
		if (0 == strncmp (buf, "cs", 2))
		{
			char* status_msg = NULL;
			if (strlen(buf) > 3)
			{
				status_msg = (char*)malloc(strlen(buf)-1);
				memcpy (status_msg, buf+3, strlen(buf)-2);
			}
			gg_change_mood (0, status_msg);
		}
		else if (0 == strncmp (buf, "sn", 2))
		{
			if (strlen (buf) > 3)
			{
				char* rec = (char*)malloc(strlen(buf)-1);
				memcpy (rec, buf+3, strlen(buf)-2);
				gg_recipient = atoi (rec);
			}

		}
		else if (0 == strncmp (buf, "sm", 2))
		{
			char* msg = NULL;
			if (2 < strlen (buf))
			{
				msg = new char[strlen(buf)-3+1]; // +1
				memcpy (msg, buf+3, strlen(buf)-2);
				msg[strlen (buf)-3] = 0x0;
				gg_send_message (gg_recipient, msg);
			}
		}
		else if (0 == strcmp (buf, "help"))
		{
			printf ("Available commands: \n");
			printf ("\tcs <status>\t\tsets user status\n");
			printf ("\tsr <uin>\t\tset receipent number\n");
			printf ("\tsm <uin>\t\tsend message to receipent\n");
			printf ("\thelp\t\t\tdisplays this message\n\n");
		}
		else if (0 == strncmp (buf, "quit", 4))
		{	quit = true;
		}
	}
}

int main (int argc, char** argv)
{
	pthread_t receive_thread, command_thread, ping_thread;
	struct gg_welcome welcome;
    struct gg_login login;
	struct gg_login_resp login_resp;
    struct sockaddr_in server;
	struct termios oflags, nflags;
	char* uinv = NULL;
	int r;	

	while ((r = getopt(argc, argv, "u:p:")) != -1)
	{
		switch (r)
		{
			case 'u':
				gg_uin = atof (optarg);
				if (!gg_uin)
				{
					printf ("Error: UIN %s is invalid!\n", optarg);
					abort();
				}
				printf ("Using UIN: %d\n", gg_uin);
				break;
			case 'p':
				gg_password = (char*)malloc(64);
				strncpy (gg_password, optarg, 63);
				printf ("Using password: %s\n", gg_password);
				break;
			case '?':
				if (optopt == 'u')
 					printf ("Option -%c requires an argument.\n", optopt);
				else if (isprint(optopt))
					printf ("Unknown option `-%c'.\n", optopt);
				else 
					printf ("Unknown option character `\\x%x'.\n", optopt);
				return 1;
			default:
				abort();
		}
	}

    server.sin_family = AF_INET;
    server.sin_port = htons ((u_short)8074);
    server.sin_addr.s_addr = inet_addr ("91.214.237.15");
    memset (&(server.sin_zero), 0x0, 8);
        
	sock_fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (-1 == sock_fd)
    {
		perror ("socket() error lol!");
		exit (1);
    }
                
    if (-1 == connect (sock_fd, (struct sockaddr *)&server, sizeof (struct sockaddr)))
    {
    	perror ("connect() error lol!");
		exit (1);
    }
        
    gg_clear_header (&header);                
    if (0 >= recv (sock_fd, (char *)&header, sizeof (header), 0))
    {
		perror ("recv() error lol! [welcome msg]");
		exit (1);
	}

    if (0 > recv (sock_fd, (char *)&welcome, header.length, 0))
    {
		perror ("recv() error lol! [welcome msg]");
		exit (1);
	}

	if (!gg_uin)
	{
		printf ("No UID specified!\nEnter your UIN: ");
		scanf ("%d", &gg_uin);
	}

	// For password prompt
	tcgetattr (fileno(stdin), &oflags);
	nflags = oflags;
	nflags.c_lflag &= ~ECHO;
	nflags.c_lflag |= ECHONL;
	if (0 != tcsetattr(fileno(stdin), TCSANOW, &nflags))
	{
		perror ("tcsetattr");
		abort();
	}

	if (!gg_password)
	{
		gg_password = (char*)malloc(64);
		printf ("No password supplied!\nEnter password: ");
		gg_password = (char*)malloc(63);
		scanf ("%31s", gg_password);
	}

	// Restore echoing entered strings
	if (0 != tcsetattr(fileno(stdin), TCSANOW, &oflags))
	{
		perror ("tcsetattr");
		abort();
	}

	printf ("Trying to log in ... (UIN = %d)\n", gg_uin);
    gg_clear_header (&header);
    header.type = GG_LOGIN;
    header.length = sizeof (login);

    login.uin = gg_uin;
	login.language = {'p', 'l'};
    login.hash_type = 0x02;
    sprintf (login.hash, gg_sha_hash (gg_password, welcome.seed));
    for (unsigned int i = sizeof(login.hash); i > strlen(login.hash); i--)
    {	login.hash[i] = 0x0; // XXX ?
    }
    login.status = 0x0002;
    login.flags = 0;
    login.features = 0x00000367;
    login.local_ip = 0;
    login.local_port = 0;
    login.external_ip = 0;
    login.external_port = 0;
    login.image_size = 64;
    login.unknown1 = 0x64;
    login.version_len = 0x23;
    sprintf(login.version, "Gadu-Gadu Client build 10.0.0.10450");
    login.desc_s = 0;
    login.desc[0] = 0x0;
 
    if (0 > send (sock_fd, (char *)&header, sizeof(header), 0))
    {
		perror ("send() error lol! [login header]");
		exit (1);
	}
                
    if (0 > send(sock_fd, (char *)&login, sizeof(login), 0))
    {
		perror ("send() error lol! [login struct]");
		exit (1);
	}

	bool login_ok = false;
	gg_clear_header (&header);
    if (recv (sock_fd, (char *)&header, sizeof(header), 0) > 0)
    {
    	if(header.type == GG_LOGIN_OK)
    	{
    		printf ("Logged in ... (uin=%d)\n", gg_uin);
			recv (sock_fd, (char *)&login_resp, sizeof (login_resp), 0);	
			login_ok = true;
    	} 
		else if (GG_LOGIN_FAILED == header.type)
		{
			perror ("login failed!");
			exit (1);
    	}
		else 
		{
			perror ("unknown login response!");
			exit (1);
    	}
    }

	if (login_ok)
	{
		pthread_create (&command_thread, NULL, gg_command_loop, NULL);
		pthread_create (&receive_thread, NULL, gg_receive_loop, NULL);
		pthread_create (&ping_thread, NULL, gg_pingpong_loop, NULL);

		pthread_join (command_thread, NULL);
		quit_app = true;
	}

    close (sock_fd);
	return 0;
}

char* gg_sha_hash (const char* password, int seed)
{
    SHA_CTX ctx;
    static char result[20];
          
    SHA1_Init(&ctx);  
    SHA1_Update(&ctx, password, strlen(password));
    SHA1_Update(&ctx, &seed, sizeof(seed));
    SHA1_Final((unsigned char *)result, &ctx);

    return result;
}

void gg_clear_header (struct gg_header* h)
{
    h->type = 0;
	h->length = 0;
}

