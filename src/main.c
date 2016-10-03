/*******************************************************************************
 *
 *                             Messenger Backend
 *     Copyright (C) 2016 Björn Petersen Software Design and Development
 *                   Contact: r10s@b44t.com, http://b44t.com
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see http://www.gnu.org/licenses/ .
 *
 *******************************************************************************
 *
 * File:    main.c
 * Authors: Björn Petersen
 * Purpose: Testing frame; if used as a lib, this file is obsolete.
 *
 *******************************************************************************
 *
 * Usage:  messenger-backend <databasefile>
 * (for "Code::Blocks, use Project / Set programs' arguments")
 * all further options can be set using the set-command (type ? for help).
 *
 ******************************************************************************/


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "mrmailbox.h"
#include "mrtools.h"


static char* read_cmd()
{
	printf("> ");
	static char cmdbuffer[1024];
	fgets(cmdbuffer, 1000, stdin);

	while( strlen(cmdbuffer)>0
	 && (cmdbuffer[strlen(cmdbuffer)-1]=='\n' || cmdbuffer[strlen(cmdbuffer)-1]==' ') )
	{
		cmdbuffer[strlen(cmdbuffer)-1] = '\0';
	}

	return cmdbuffer;
}


static void print_error()
{
	printf("ERROR.\n");
}


int main(int argc, char ** argv)
{
	mrmailbox_t* mailbox = mrmailbox_new();
	mrchat_t*    sel_chat = NULL;

	printf("LibreChat is awaiting your commands.\n");

	/* open database from the commandline (if omitted, it can be opened using the `open`-command) */
	if( argc == 2 ) {
		if( !mrmailbox_open(mailbox, argv[1], NULL) ) {
			print_error();
		}
	}
	else if( argc != 1 ) {
		printf("Error: Bad arguments\n");
	}

	/* wait for command */
	while(1)
	{
		/* read command */
		const char* cmd = read_cmd();

		if( strcmp(cmd, "help")==0 || cmd[0] == '?' )
		{
			printf("?                   show this help\n");
			printf("open <file>         open/create database\n");
			printf("close               close database\n");
			printf("import [<spec>]     import file/folder/last EML-file(s)\n");
			printf("set <key> [<value>] set/delete configuration value\n");
			printf("get <key>           show configuration value\n");
			printf("connect             connect to mailbox server\n");
			printf("disconnect          disconnect from mailbox server\n");
			printf("fetch               fetch messages\n");
			printf("info                show database information\n");
			printf("chats               list all chats\n");
			printf("chat [<spec>]       list chat/select chat by id\n");
			printf("send <text>         send message to selected chat\n");
			printf("draft [<text>]      save/delete draft in selected chat\n");
			printf("empty               empty database but server config\n");
			printf("clear               clear screen\n");
			printf("exit                exit program\n");
		}
		else if( strncmp(cmd, "clear", 5)==0 )
		{
			printf("\n\n\n\n"); /* insert some blank lines to visualize the break in the buffer */
			printf("\e[1;1H\e[2J"); /* should work on ANSI terminals and on Windows 10. If not, well, then not. */
		}
		else if( strncmp(cmd, "open", 4)==0 )
		{
			const char* p1 = strstr(cmd, " ");
			if( p1 ) {
				p1++;
				mrmailbox_close(mailbox);
				if( !mrmailbox_open(mailbox, p1, NULL) ) {
					print_error();
				}
			}
			else {
				printf("ERROR: Argument <file> missing.\n");
			}
		}
		else if( strcmp(cmd, "close")==0 )
		{
			if( mrmailbox_is_open(mailbox) ) {
				mrmailbox_close(mailbox);
			}
			else {
				printf("ERROR: no database opened.\n");
			}
		}
		else if( strncmp(cmd, "import", 6)==0 )
		{
			const char* arg1 = strstr(cmd, " ");
			if( !mrmailbox_import_spec(mailbox, arg1? ++arg1 : NULL) ) {
				print_error();
			}
		}
		else if( strcmp(cmd, "connect")==0 )
		{
			if( !mrmailbox_connect(mailbox) ) {
				print_error();
			}
		}
		else if( strcmp(cmd, "disconnect")==0 )
		{
			mrmailbox_disconnect(mailbox);
		}
		else if( strcmp(cmd, "fetch")==0 )
		{
			if( !mrmailbox_fetch(mailbox) ) {
				print_error();
			}
		}
		else if( strncmp(cmd, "set", 3)==0 )
		{
			char* arg1 = (char*)strstr(cmd, " ");
			if( arg1 ) {
				arg1++;
				char* arg2 = strstr(arg1, " ");
				if( arg2 ) {
					*arg2 = 0;
					arg2++;
				}
				if( !mrmailbox_set_config(mailbox, arg1, arg2) ) {
					print_error();
				}
			}
			else {
				printf("ERROR: Argument <key> missing.\n");
			}
		}
		else if( strncmp(cmd, "get", 3)==0 )
		{
			char* arg1 = (char*)strstr(cmd, " ");
			if( arg1 ) {
				arg1++;
				char* ret = mrmailbox_get_config(mailbox, arg1, "<unset>");
				if( ret ) {
					printf("%s=%s\n", arg1, ret);
					free(ret);
				}
				else {
					print_error();
				}
			}
			else {
				printf("ERROR: Argument <key> missing.\n");
			}
		}
		else if( strcmp(cmd, "info")==0 )
		{
			char* buf = mrmailbox_get_info(mailbox);
			if( buf ) {
				printf("%s", buf);
				free(buf);
			}
			else {
				print_error();
			}
		}
		else if( strcmp(cmd, "chats")==0 )
		{
			mrchatlist_t* chatlist = mrmailbox_get_chatlist(mailbox);
			if( chatlist ) {
				int i, cnt = carray_count(chatlist->m_chats);
				if( cnt ) {
					printf("================================================================================\n");
					for( i = 0; i < cnt; i++ )
					{
						mrchat_t* chat = (mrchat_t*)carray_get(chatlist->m_chats, i);
						char *temp;

						temp = mrchat_get_subtitle(chat);
							printf("Chat #%i: %s [%s] [%i unread]\n", (int)chat->m_id, chat->m_name, temp, (int)mrchat_get_unread_count(chat));
						free(temp);

						mrpoortext_t* temp2 = mrchat_get_last_summary(chat);
							if( temp2->m_title ) { printf("%s(%i): ", temp2->m_title, temp2->m_title_meaning); }
							if( temp2->m_text ) { printf("%s", temp2->m_text); }
						mrpoortext_unref(temp2);

						int laststate = mrchat_get_last_state(chat);
						switch( laststate ) {
							case MR_OUT_PENDING:   printf(" o"); break;
							case MR_OUT_DELIVERED: printf(" √"); break;
							case MR_OUT_READ:      printf(" √√"); break;
						}

						char* temp3 = mr_timestamp_to_str(mrchat_get_last_timestamp(chat));
							printf(" [%s]\n", temp3);
						free(temp3);

						printf("================================================================================\n");
					}
				}
				else {
					printf("Empty chat list.\n");
				}
				mrchatlist_unref(chatlist);
			}
			else {
				printf("No chats.\n");
			}
		}
		else if( strncmp(cmd, "chat", 4)==0 )
		{
			char* arg1 = (char*)strstr(cmd, " ");
			if( arg1 && arg1[0] ) {
				/* select a chat (argument 1 = name of chat to select) */
				arg1++;
				if( sel_chat ) { mrchat_unref(sel_chat); sel_chat = NULL; }
				sel_chat = mrmailbox_get_chat_by_id(mailbox, atoi(arg1)); /* may be NULL */
			}

			/* show chat */
			if( sel_chat ) {
				mrmsglist_t* msglist = mrchat_get_msglist(sel_chat, 0, 100);
				char* temp2 = mrchat_get_subtitle(sel_chat);
					printf("Chat #%i: %s [%s]\n", sel_chat->m_id, sel_chat->m_name, temp2);
				free(temp2);
				if( msglist ) {
					int i, cnt = carray_count(msglist->m_msgs);
					printf("--------------------------------------------------------------------------------\n");
					for( i = 0; i < cnt; i++ )
					{
						mrmsg_t* msg = (mrmsg_t*)carray_get(msglist->m_msgs, i);
						temp2 = mr_timestamp_to_str(msg->m_timestamp);
							printf("Msg #%i: %s [%s]\n", (int)msg->m_id, msg->m_msg, temp2);
						free(temp2);
						printf("--------------------------------------------------------------------------------\n");
					}
					mrmsglist_unref(msglist);
				}
				if( sel_chat->m_draft_timestamp ) {
					char* timestr = mr_timestamp_to_str(sel_chat->m_draft_timestamp);
						printf("Draft: %s [%s]\n", sel_chat->m_draft_msg, timestr);
					free(timestr);
				}
			}
			else {
				printf("No chat selected.\n");
			}
		}
		else if( strncmp(cmd, "draft", 5)==0 )
		{
			if( sel_chat ) {
				char* arg1 = (char*)strstr(cmd, " ");
				if( arg1 && arg1[0] ) {
					arg1++;
					mrchat_save_draft(sel_chat, arg1);
					printf("Draft saved.\n");
				}
				else {
					mrchat_save_draft(sel_chat, NULL);
					printf("Draft deleted.\n");
				}
			}
			else {
				printf("No chat selected.\n");
			}
		}
		else if( strncmp(cmd, "send", 4)==0 )
		{
			if( sel_chat ) {
				char* arg1 = (char*)strstr(cmd, " ");
				if( arg1 && arg1[0] ) {
					mrmsg_t* msg = mrmsg_new(mailbox);
						arg1++;
						msg->m_msg = strdup(arg1);
						mrchat_send_msg(sel_chat, msg);
					mrmsg_unref(msg);
				}
				else {
					printf("No message text given.\n");
				}
			}
			else {
				printf("No chat selected.\n");
			}
		}
		else if( strcmp(cmd, "empty")==0 )
		{
			if( !mrmailbox_empty_tables(mailbox) ) {
				print_error();
			}
		}
		else if( strcmp(cmd, "exit")==0 )
		{
			break;
		}
		else if( cmd[0] == 0 )
		{
			; /* nothing types */
		}
		else
		{
			printf("ERROR: Unknown command \"%s\", type ? for help.\n", cmd);
		}
	}

	if( sel_chat ) { mrchat_unref(sel_chat); sel_chat = NULL; }
	mrmailbox_close(mailbox);
	mrmailbox_unref(mailbox);
	mailbox = NULL;
	return 0;
}


