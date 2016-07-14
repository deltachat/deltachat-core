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
 ******************************************************************************/


#include <stdio.h>
#include <string.h>
#include "mrmailbox.h"



char* readcmd()
{
	printf("> ");
	static char cmdbuffer[1024];
	fgets(cmdbuffer, 1000, stdin);
    if ((strlen(cmdbuffer)>0) && (cmdbuffer[strlen(cmdbuffer) - 1] == '\n'))
        cmdbuffer[strlen(cmdbuffer) - 1] = '\0';
	return cmdbuffer;
}

int main()
{
	MrMailbox* mailbox = new MrMailbox();

	mailbox->Open("/home/bpetersen/temp/foobar.db");

	printf("*************************************************\n");
	printf("Messenger Backend v%i.%i.%i\n", (int)MR_VERSION_MAJOR, (int)MR_VERSION_MINOR, (int)MR_VERSION_REVISION);
	printf("*************************************************\n");
	while(1)
	{
		// read command
		const char* cmd = readcmd();

		if( strcmp(cmd, "help")==0 || cmd[0] == '?' )
		{
			printf("?                 : show this help\n");
			printf("open <file>       : open database\n");
			printf("close             : close database\n");
			printf("set <key> <value> : set configuration value\n");
			printf("get <key>         : show configuration value\n");
			printf("connect           : connect to mailbox server\n");
			printf("info              : show database information\n");
			printf("quit              : quit\n");
		}
		else if( strncmp(cmd, "open", 4)==0 )
		{
			const char* p1 = strstr(cmd, " ");
			if( p1 ) {
				p1++;
				mailbox->Close();
				mailbox->Open(p1);
			}
			else {
				printf("Argument missing.\n");
			}
		}
		else if( strcmp(cmd, "close")==0 )
		{
			mailbox->Close();
		}
		else if( strcmp(cmd, "info")==0 )
		{
			char* filename = mailbox->GetDbFile();
			if( filename )
			{
				printf("Database file: %s\n", filename);
				free(filename);
			}
			else
			{
				printf("Database file: none\n");
				free(filename);
			}
		}
		else if( strcmp(cmd, "exit")==0 )
		{
			printf("Bye!\n");
			break;
		}
		else
		{
			printf("Unknown command \"%s\", type ? for help.\n", cmd);
		}
	}

	mailbox->Close();
	delete mailbox;
    return 0;
}


