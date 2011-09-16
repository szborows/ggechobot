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

#ifndef GG_H
#define GG_H

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/sha.h> // OpenSSL - SHA1
#include <pthread.h> 	// POSIX threads
#include <stdlib.h>
#include <termios.h>

/* GG protocol defines */

#define GG_PACKED 					__attribute__((packed))
#define GG_WELCOME 					0x0001
#define GG_LOGIN 					0x0031
#define GG_LOGIN_OK 				0x0035
#define GG_LOGIN_FAILED 			0x0043
#define GG_MAX_MESSAGE_LENGTH		0x0100

#define GG_NEW_STATUS80				0x0038
#define GG_STATUS_NOT_AVAIL			0x0001
#define GG_STATUS_NOT_AVAIL_DESCR	0x0015
#define GG_STATUS_FFC				0x0017	// "Talk with me" status
#define GG_STATUS_FFC_DESCR			0x0018
#define GG_STATUS_AVAIL				0x0002
#define GG_STATUS_AVAIL_DESCR		0x0004
#define GG_STATUS_BUSY				0x0003
#define GG_STATUS_BUSY_DESCR		0x0005
#define GG_STATUS_DND				0x0021	// "Do not disturb" status
#define GG_STATUS_DND_DESCR			0x0022
#define GG_STATUS_INVISIBLE			0x0014
#define GG_STATUS_INVISIBLE_DESCR	0x0016
#define GG_STATUS_BLOCKED			0x0006
#define GG_STATUS_IMAGE_MASK		0x0100
#define GG_STATUS_ADAPT_STATUS_MASK	0x0400	// ?
#define GG_STATUS_DESCR_MASK		0x4000	// is description available?
#define GG_STATUS_FRIENDS_MASK		0x8000	// visible only for friends?

#define GG_SEND_MSG80 				0x002d
#define GG_LIST_EMPTY 				0x0012
#define GG_XML_ACTION				0x002c
#define GG_USER_DATA				0x0044
#define GG_NOTIFY_REPLY80			0x0037
#define GG_RECV_MSG_ACK				0x0046
#define GG_RECV_MSG80 				0x002e
#define GG_SEND_MSG_ACK 			0x0005
#define GG_PING						0x0008
#define GG_PONG						0x0007

/*! 
 *  Basic GG protocol header. It predict type and length of next packet.
 */

struct gg_header
{
        int type;
        int length;      
} GG_PACKED;

static int sock_fd = 0;					// socket description
static int gg_uin = 32139726;			// bot default UIN
static char* gg_password = NULL;		// bot default password
static struct gg_header header, rheader;
static int gg_recipient = 8349954;		// bot default receiver
static bool quit_app = false;

/*!
 * Thread function for handling commands from user.
 */

void* 	gg_command_loop (void* user_data);

/*!
 * Gets the list of contacts from server.
 */

void 	gg_get_list (void);

/*!
 * \biref Sends message.
 * \param uin UIN of receiver
 * \param html_message message in HTML format
 */

void 	gg_send_message (int uin, char* html_message);

/*!
 * Thread function for handling incoming packets.
 */

void* 	gg_receive_loop (void* user_data);

/*!
 * Changes user status description along with mood icon.
 */

void 	gg_change_mood (int m, char* status_msg = NULL);

/*!
 * Simple function to zero GG header.
 */

void 	gg_clear_header (struct gg_header* h);

/*!
 * Generate SHA1 hash basing on given password and seed.
 * \param password to hash
 * \param seed to use
 * \return SHA1 null-terminated hash string
 */

char* 	gg_sha_hash (const char* password, int seed);


struct gg_send_msg_ack 
{
	int status;
	int recipient;
	int seq;
};

struct gg_recv_msg80 
{
	int sender;
	int seq;
	int time;
	int _class;
	int offset_plain;
	int offset_attributes;
	char text[];
};

struct gg_welcome 
{
	int seed;
} GG_PACKED;

struct gg_login
{
        int uin;            /* nr */
        char language[2];   /* "pl" */
        char hash_type;     /* 0x02 - sha1; 0x01 - older ver. */
        char hash[64];      /* hash; null-terminated */
        int status;         /* 0x0002 */
        int flags;          /* c**** wi, 0 */
        int features;       /* 0x00000367 */
        int local_ip;       /*0*/
        short local_port;   /*0*/
        int external_ip;    /*0*/
        short external_port;/*0*/
        char image_size;    /* maximum size of graphic */
        char unknown1;      /* 0x64 */
        int version_len;    /* ver.info.len, 0x23 */
        char version[36];   /* "Gadu-Gadu Client build 10.0.0.10450" */
        int desc_s;         /* len. of description */
        char desc[8];       /* status desc. */
} GG_PACKED;

struct gg_login_resp
{
	int unknown1;
} GG_PACKED;

struct gg_new_status80
{
	int status;
	int flags;
	int description_size;
} GG_PACKED;

struct gg_send_msg80 
{
	int recipient;
	int seq;
	int _class;
	int offset_plain;
	int offset_attributes;
} GG_PACKED;

#endif
