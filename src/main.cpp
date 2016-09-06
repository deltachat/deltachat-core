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
 * File:    main.cpp
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


static char* str_repeat(const char* str, int multiplier)
{
	int str_len = strlen(str);
	int bytes_needed = str_len * multiplier;
	if( bytes_needed <= 0 ) {
		return strdup("");
	}

	char* buf = (char*)malloc(bytes_needed+1);
	char* p1 = buf;
	while( multiplier )
	{
		strcpy(p1, str);
		p1 = &p1[str_len];
		multiplier--;
	}

	return buf;
}


int main(int argc, char ** argv)
{
	MrMailbox* mailbox = new MrMailbox();
	MrChat*    sel_chat = NULL;

	printf("LibreChat is awaiting your commands.\n");

	// open database from the commandline (if omitted, it can be opened using the `open`-command)
	if( argc == 2 ) {
		if( !mailbox->Open(argv[1]) ) {
			print_error();
		}
	}
	else if( argc != 1 ) {
		printf("Error: Bad arguments\n");
	}

	// wait for command
	while(1)
	{
		// read command
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
			printf("chat [<spec>]       list chat/select chat by name or id\n");
			printf("send <text>         send message to selected chat\n");
			printf("empty               empty database but server config\n");
			printf("exit                exit program\n");
		}
		else if( strncmp(cmd, "open", 4)==0 )
		{
			const char* p1 = strstr(cmd, " ");
			if( p1 ) {
				p1++;
				mailbox->Close();
				if( !mailbox->Open(p1) ) {
					print_error();
				}
			}
			else {
				printf("ERROR: Argument <file> missing.\n");
			}
		}
		else if( strcmp(cmd, "close")==0 )
		{
			char* filename;
			if( (filename=mailbox->GetDbFile()) != NULL ) {
				free(filename);
				mailbox->Close();
			}
			else {
				printf("ERROR: no database opened.\n");
			}
		}
		else if( strncmp(cmd, "import", 6)==0 )
		{
			const char* arg1 = strstr(cmd, " ");
			if( !mailbox->ImportSpec(arg1? ++arg1 : NULL) ) {
				print_error();
			}
		}
		else if( strcmp(cmd, "connect")==0 )
		{
			if( !mailbox->Connect() ) {
				print_error();
			}
		}
		else if( strcmp(cmd, "disconnect")==0 )
		{
			mailbox->Disconnect();
		}
		else if( strcmp(cmd, "fetch")==0 )
		{
			if( !mailbox->Fetch() ) {
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
				if( !mailbox->SetConfig(arg1, arg2) ) {
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
				char* ret = mailbox->GetConfig(arg1, "<unset>");
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
			char* buf = mailbox->GetInfo();
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
			MrChatList* chatlist = mailbox->GetChats();
			if( chatlist ) {
				int i, cnt = carray_count(chatlist->m_chats);
				if( cnt ) {
					for( i = 0; i < cnt; i++ )
					{
						MrChat* chat = (MrChat*)carray_get(chatlist->m_chats, i);
						char *temp, *temp2;

						if( chat->m_lastMsg ) {
							temp = timestamp_to_str(chat->m_lastMsg->m_timestamp);
							temp2 = str_repeat("=", 77-strlen(temp));
								printf("%s%s===\n", temp2, temp);
							free(temp2);
							free(temp);
						}

						temp = chat->GetSubtitle();
							printf("%i: %s [%s]\n", (int)chat->m_id, chat->m_name, temp);
						free(temp);

						temp = chat->GetLastMsgExcerpt();
							printf("%s\n", temp);
						free(temp);
					}
				}
				else {
					printf("Empty chat list.\n");
				}
				delete chatlist;
			}
			else {
				printf("No chats.\n");
			}
		}
		else if( strncmp(cmd, "chat", 4)==0 )
		{
			char* arg1 = (char*)strstr(cmd, " ");
			if( arg1 && arg1[0] ) {
				// select a chat (argument 1 = name of chat to select)
				arg1++;
				if( sel_chat ) { delete sel_chat; sel_chat = NULL; }
				if( atoi(arg1) > 0 ) {
					sel_chat = mailbox->GetChat(atoi(arg1)); // may be NULL
				}
				else {
					sel_chat = mailbox->GetChat(arg1); // may be NULL
				}
			}

			// show chat
			if( sel_chat ) {
				printf("Chat name: %s\n", sel_chat->m_name);
				MrMsgList* msglist = sel_chat->ListMsgs();
				if( msglist ) {
					int i, cnt = carray_count(msglist->m_msgs);
					for( i = 0; i < cnt; i++ ) {
						MrMsg* msg = (MrMsg*)carray_get(msglist->m_msgs, i);
						char *temp, *temp2;

						temp = timestamp_to_str(msg->m_timestamp);
						temp2 = str_repeat(msg->m_fromId==0/*0=self*/? "<" : ">", 79-strlen(temp));
							printf("%s %s\n", temp2, temp);
						free(temp2);
						free(temp);

						temp = safe_strdup(msg->m_msg);
							mr_shorten_str(temp, 80);
							printf("%s\n", temp);
						free(temp);
					}
					delete msglist;
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
					arg1++;
					sel_chat->SendMsg(arg1);
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
			if( !mailbox->Empty() ) {
				print_error();
			}
		}
		else if( strcmp(cmd, "exit")==0 )
		{
			break;
		}
		else if( cmd[0] == 0 )
		{
			; // nothing types
		}
		else
		{
			printf("ERROR: Unknown command \"%s\", type ? for help.\n", cmd);
		}
	}

	if( sel_chat ) { delete sel_chat; sel_chat = NULL; }
	mailbox->Close();
	delete mailbox;
	mailbox = NULL;
	return 0;
}


