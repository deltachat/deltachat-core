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


static uintptr_t receive_event(mrmailbox_t* mailbox, int event, uintptr_t data1, uintptr_t data2)
{
	switch( event ) {
		case MR_EVENT_IS_EMAIL_KNOWN:
			printf("{{Received event #%i, MR_EVENT_IS_EMAIL_KNOWN (%s, %i)}}\n", (int)event, (const char*)data1, (int)data2);
			return 1;
			break;

		default:
			printf("{{Received event #%i (%i, %i)}}\n", (int)event, (int)data1, (int)data2);
			break;
	}

	return 0;
}


int main(int argc, char ** argv)
{
	mrmailbox_t* mailbox = mrmailbox_new(receive_event, NULL);
	mrchat_t*    sel_chat = NULL;

	printf("Messenger Backend is awaiting your commands.\n"); /* use neutral speach here, the messenger backend is not directly related to any front end or end-product. */

	/* open database from the commandline (if omitted, it can be opened using the `open`-command) */
	if( argc == 2 ) {
		if( !mrmailbox_open(mailbox, argv[1], NULL) ) {
			printf("ERROR: Cannot open mailbox.\n");
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
			printf("configure           configure server connection\n");
			printf("connect             connect to server\n");
			printf("disconnect          disconnect from server\n");
			printf("fetch               fetch messages\n");
			printf("info                show database information\n");
			printf("chats               list all chats\n");
			printf("chat [<id>]         list chat/select chat by id\n");
			printf("send <text>         send message to selected chat\n");
			printf("draft [<text>]      save/delete draft in selected chat\n");
			printf("event <id>          test the given event\n");
			printf("empty               empty database but server config\n");
			printf("clear               clear screen\n");
			printf("exit                exit program\n");
		}
		else if( strncmp(cmd, "clear", 5)==0 )
		{
			printf("\n\n\n\n"); /* insert some blank lines to visualize the break in the buffer */
			printf("\e[1;1H\e[2J"); /* should work on ANSI terminals and on Windows 10. If not, well, then not. */
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

						mrpoortext_t* poortext = mrchat_get_summary(chat);

							if( poortext->m_title ) { printf("%s: ", poortext->m_title); }
							if( poortext->m_text ) { printf("%s", poortext->m_text); }

							switch( poortext->m_state ) {
								case MR_OUT_PENDING:   printf(" o"); break;
								case MR_OUT_DELIVERED: printf(" √"); break;
								case MR_OUT_READ:      printf(" √√"); break;
							}

							char* temp3 = mr_timestamp_to_str(poortext->m_timestamp);
								printf(" [%s]\n", temp3);
							free(temp3);

						mrpoortext_unref(poortext);

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
						mrcontact_t* contact = mrmailbox_get_contact_by_id(mailbox, msg->m_from_id);
						const char* contact_name = (contact && contact->m_name)? contact->m_name : "ErrName";

						temp2 = mr_timestamp_to_str(msg->m_timestamp);
							printf("Msg #%i: %s: %s [%s]\n", (int)msg->m_id, contact_name, msg->m_text, temp2);
						free(temp2);

						mrcontact_unref(contact);
						printf("--------------------------------------------------------------------------------\n");
					}
					mrmsglist_unref(msglist);
				}
				if( sel_chat->m_draft_timestamp ) {
					char* timestr = mr_timestamp_to_str(sel_chat->m_draft_timestamp);
						printf("Draft: %s [%s]\n", sel_chat->m_draft_text, timestr);
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
						msg->m_text = strdup(arg1);
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
		else if( strcmp(cmd, "exit")==0 )
		{
			break;
		}
		else if( cmd[0] == 0 )
		{
			; /* nothing typed */
		}
		else
		{
			char* execute_result = mrmailbox_execute(mailbox, cmd);
			if( execute_result ) {
				printf("%s\n", execute_result);
				free(execute_result);
			}
			else {
				printf("ERROR: Unknown command \"%s\", type ? for help.\n", cmd);
			}
		}
	}

	if( sel_chat ) { mrchat_unref(sel_chat); sel_chat = NULL; }
	mrmailbox_close(mailbox);
	mrmailbox_unref(mailbox);
	mailbox = NULL;
	mrstock_exit();
	return 0;
}


