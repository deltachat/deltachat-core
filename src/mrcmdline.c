/*******************************************************************************
 *
 *                             Messenger Backend
 *                      Copyright (C) 2017 Björn Petersen
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
 * File:    mrcmdline.c
 * Purpose: implement mrmailbox_cmdline(), this file is optional
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include "mrmailbox.h"
#include "mrcmdline.h"
#include "mrlog.h"
#include "mrtools.h"


static void log_msglist(mrmailbox_t* mailbox, carray* msglist)
{
	int i, cnt = carray_count(msglist), lines_out = 0;
	for( i = 0; i < cnt; i++ )
	{
		uint32_t msg_id = (uint32_t)(uintptr_t)carray_get(msglist, i);
		if( msg_id == MR_MSG_ID_DAYMARKER ) {
			mrlog_info("--------------------------------------------------------------------------------"); lines_out++;
		}
		else if( msg_id > 0 ) {
			if( lines_out==0 ) { mrlog_info("--------------------------------------------------------------------------------"); lines_out++; }

			mrmsg_t* msg = mrmailbox_get_msg(mailbox, msg_id);
			mrcontact_t* contact = mrmailbox_get_contact(mailbox, msg->m_from_id);
			const char* contact_name = (contact && contact->m_name)? contact->m_name : "ErrName";
			int contact_id = contact? contact->m_id : 0;

			char* temp2 = mr_timestamp_to_str(msg->m_timestamp);
				mrlog_info("Msg #%i: %s (Contact #%i): %s %s[%s]", (int)msg->m_id, contact_name, contact_id, msg->m_text,
					msg->m_from_id==1? "" : (msg->m_state==MR_IN_SEEN? "[SEEN]":"[UNSEEN]"),
					temp2);
			free(temp2);

			mrcontact_unref(contact);
			mrmsg_unref(msg);
		}
	}

	if( lines_out > 0 ) { mrlog_info("--------------------------------------------------------------------------------"); }
}


char* mrmailbox_cmdline(mrmailbox_t* mailbox, const char* cmd)
{
	#define      COMMAND_FAILED    ((char*)1)
	#define      COMMAND_SUCCEEDED ((char*)2)
	#define      COMMAND_UNKNOWN   ((char*)3)
	char*        ret = COMMAND_FAILED;
	mrchat_t*    sel_chat = NULL;

	if( mailbox == NULL || cmd == NULL || cmd[0]==0 ) {
		goto cleanup;
	}

	if( mailbox->m_cmdline_sel_chat_id ) {
		sel_chat = mrmailbox_get_chat(mailbox, mailbox->m_cmdline_sel_chat_id);
	}

	if( strcmp(cmd, "help")==0 || cmd[0] == '?' )
	{
		ret = safe_strdup(
			"Database commands:\n"
			"open <file>         open/create database\n"
			"close               close database\n"
			"empty               empty database but server config\n"
			"import [<spec>]     import file/folder/last EML-file(s)\n"
			"set <key> [<value>] set/delete configuration value\n"
			"get <key>           show configuration value\n"
			"configure           configure server connection\n"
			"connect             connect to server\n"
			"disconnect          disconnect from server\n"
			"fetch               fetch messages\n"
			"restore <days>      restore messages of the last days\n"
			"info                show database information\n"
			"\n"
			"Chat commands:\n"
			"chats [<query>]     list chats\n"
			"chat [<id>]         list chat/select chat by id/deselect with id 0\n"
			"createchat <id>     create chat by the given contact id\n"
			"creategroup <name>  create group with name\n"
			"addmember <id>      add contact to group\n"
			"removemember <id>   remove contact from group\n"
			"send <text>         send message to selected chat\n"
			"sendimage <file>    send image to selected chat\n"
			"search <query>      search messages in the selected chat or globally\n"
			"draft [<text>]      save/delete draft in selected chat\n"
			"showmedia           show media in selected chat\n"
			"delchat <id>        delete chat\n"
			"\n"
			"Message commands\n"
			"msginfo <id>        show message information\n"
			"unseen              list unseen messages\n"
			"markseen <id>       mark message as seen\n"
			"delmsg <id>         delete message\n"
			"\n"
			"Contact commands:\n"
			"contacts [<query>]  list known contacts\n"
			"adr <name>;<addr>   add entry to address book\n"
			"\n"
			"Misc.:\n"
			"event <id>          test the given event\n"
			"fileinfo <file>     show eg. width/height of the given file\n"
			"clear               clear screen\n" /* must be implemented by  the caller */
			"exit                exit program\n" /* must be implemented by  the caller */
			"?                   show this help"
		);
	}


	/*******************************************************************************
	 * Database commands
	 ******************************************************************************/

	else if( strncmp(cmd, "open", 4)==0 )
	{
		const char* arg1 = strstr(cmd, " ");
		if( arg1 ) {
			arg1++;
			mrmailbox_close(mailbox);
			ret = mrmailbox_open(mailbox, arg1, NULL)? COMMAND_SUCCEEDED : COMMAND_FAILED;
		}
		else {
			ret = safe_strdup("ERROR: Argument <file> missing.");
		}
	}
	else if( strcmp(cmd, "close")==0 )
	{
		mrmailbox_close(mailbox);
		ret = COMMAND_SUCCEEDED;
	}
	else if( strcmp(cmd, "empty")==0 )
	{
		ret = mrmailbox_empty_tables(mailbox)? COMMAND_SUCCEEDED : COMMAND_FAILED;
	}
	else if( strncmp(cmd, "import", 6)==0 )
	{
		const char* arg1 = strstr(cmd, " ");
		ret = mrmailbox_import_spec(mailbox, arg1? ++arg1 : NULL)? COMMAND_SUCCEEDED : COMMAND_FAILED;
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
			ret = mrmailbox_set_config(mailbox, arg1, arg2)? COMMAND_SUCCEEDED : COMMAND_FAILED;
		}
		else {
			ret = safe_strdup("ERROR: Argument <key> missing.");
		}
	}
	else if( strncmp(cmd, "get", 3)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			arg1++;
			char* val = mrmailbox_get_config(mailbox, arg1, "<unset>");
			if( val ) {
				ret = mr_mprintf("%s=%s", arg1, val);
				free(val);
			}
			else {
				ret = COMMAND_FAILED;
			}
		}
		else {
			ret = safe_strdup("ERROR: Argument <key> missing.");
		}
	}
	else if( strcmp(cmd, "configure")==0 )
	{
		ret = mrmailbox_configure(mailbox)? COMMAND_SUCCEEDED : COMMAND_FAILED;
	}
	else if( strcmp(cmd, "connect")==0 )
	{
		ret = mrmailbox_connect(mailbox)? COMMAND_SUCCEEDED : COMMAND_FAILED;
	}
	else if( strcmp(cmd, "disconnect")==0 )
	{
		mrmailbox_disconnect(mailbox);
		ret = COMMAND_SUCCEEDED;
	}
	else if( strcmp(cmd, "fetch")==0 )
	{
		ret = mrmailbox_fetch(mailbox)? COMMAND_SUCCEEDED : COMMAND_FAILED;
	}
	else if( strncmp(cmd, "restore", 7)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			int days = atoi(arg1);
			ret = mrmailbox_restore(mailbox, days*24*60*60)? COMMAND_SUCCEEDED : COMMAND_FAILED;
		}
		else {
			ret = safe_strdup("ERROR: Argument <days> missing.");
		}
	}
	else if( strcmp(cmd, "info")==0 )
	{
		ret = mrmailbox_get_info(mailbox);
		if( ret == NULL ) {
			ret = COMMAND_FAILED;
		}
	}

	/*******************************************************************************
	 * Chat commands
	 ******************************************************************************/

	else if( strncmp(cmd, "chats", 5)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) { arg1++; }
		mrchatlist_t* chatlist = mrmailbox_get_chatlist(mailbox, arg1);
		if( chatlist ) {
			int i, cnt = mrchatlist_get_cnt(chatlist);
			if( cnt>0 ) {
				mrlog_info("================================================================================");
				for( i = 0; i < cnt; i++ )
				{
					mrchat_t* chat = mrchatlist_get_chat_by_index(chatlist, i);
					char *temp;

					temp = mrchat_get_subtitle(chat);
						mrlog_info("%s #%i: %s [%s] [%i unseen]", chat->m_type==MR_CHAT_GROUP? "Group" : "Chat",
							(int)chat->m_id, chat->m_name, temp, (int)mrchat_get_unseen_count(chat));
					free(temp);

					mrpoortext_t* poortext = mrchatlist_get_summary_by_index(chatlist, i, chat);

						const char* statestr = " ERR";
						switch( poortext->m_state ) {
							case MR_OUT_PENDING:   statestr = " o";   break;
							case MR_OUT_DELIVERED: statestr = " √";   break;
							case MR_OUT_READ:      statestr = " √√";  break;
						}

						char* timestr = mr_timestamp_to_str(poortext->m_timestamp);
							mrlog_info("%s%s%s %s [%s]",
								poortext->m_title? poortext->m_title : NULL,
								poortext->m_title? ": " : NULL,
								poortext->m_text? poortext->m_text : NULL,
								statestr, timestr
								);
						free(timestr);

					mrpoortext_unref(poortext);

					mrchat_unref(chat);

					mrlog_info("================================================================================");
				}
				ret = mr_mprintf("%i chats.", (int)cnt);
			}
			ret = mr_mprintf("%i chats.", (int)cnt);
			mrchatlist_unref(chatlist);
		}
		else {
			ret = COMMAND_FAILED;
		}
	}
	else if( strncmp(cmd, "chat", 4)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 && arg1[0] ) {
			/* select a chat (argument 1 = ID of chat to select) */
			arg1++;
			if( sel_chat ) { mrchat_unref(sel_chat); sel_chat = NULL; }
			mailbox->m_cmdline_sel_chat_id = atoi(arg1);
			sel_chat = mrmailbox_get_chat(mailbox, mailbox->m_cmdline_sel_chat_id); /* may be NULL */
			if( sel_chat==NULL ) {
				mailbox->m_cmdline_sel_chat_id = 0;
			}
		}

		/* show chat */
		if( sel_chat ) {
			carray* msglist = mrmailbox_get_chat_msgs(mailbox, sel_chat->m_id, MR_GCM_ADDDAYMARKER, 0);
			char* temp2 = mrchat_get_subtitle(sel_chat);
				mrlog_info("Chat #%i: %s [%s]", sel_chat->m_id, sel_chat->m_name, temp2);
			free(temp2);
			int msgcnt = 0;
			if( msglist ) {
				msgcnt = carray_count(msglist);
				log_msglist(mailbox, msglist);
				carray_free(msglist);
			}
			if( sel_chat->m_draft_timestamp ) {
				char* timestr = mr_timestamp_to_str(sel_chat->m_draft_timestamp);
					mrlog_info("Draft: %s [%s]", sel_chat->m_draft_text, timestr);
				free(timestr);
			}
			ret = mr_mprintf("%i messages.", msgcnt);
		}
		else {
			ret = safe_strdup("No chat selected.");
		}
	}
	else if( strncmp(cmd, "createchat ", 11)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			int contact_id = atoi(arg1);
			ret = mrmailbox_create_chat_by_contact_id(mailbox, contact_id)!=0? COMMAND_SUCCEEDED : COMMAND_FAILED;
		}
		else {
			ret = safe_strdup("ERROR: Argument <contact-id> missing.");
		}
	}
	else if( strncmp(cmd, "creategroup ", 12)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			arg1++;;
			ret = mrmailbox_create_group_chat(mailbox, arg1)!=0? COMMAND_SUCCEEDED : COMMAND_FAILED;
		}
		else {
			ret = safe_strdup("ERROR: Argument <name> missing.");
		}
	}
	else if( strncmp(cmd, "addmember ", 10)==0 )
	{
		if( sel_chat ) {
			char* arg1 = (char*)strstr(cmd, " ");
			if( arg1 ) {
				int contact_id = atoi(arg1);
				if( mrmailbox_add_contact_to_chat(mailbox, sel_chat->m_id, contact_id) ) {
					ret = safe_strdup("Contact added to chat.");
				}
				else {
					ret = safe_strdup("ERROR: Cannot add contact to chat.");
				}
			}
			else {
				ret = safe_strdup("ERROR: Argument <contact-id> missing.");
			}
		}
		else {
			ret = safe_strdup("No chat selected.");
		}
	}
	else if( strncmp(cmd, "removemember ", 10)==0 )
	{
		if( sel_chat ) {
			char* arg1 = (char*)strstr(cmd, " ");
			if( arg1 ) {
				int contact_id = atoi(arg1);
				if( mrmailbox_remove_contact_from_chat(mailbox, sel_chat->m_id, contact_id) ) {
					ret = safe_strdup("Contact added to chat.");
				}
				else {
					ret = safe_strdup("ERROR: Cannot remove member from chat.");
				}
			}
			else {
				ret = safe_strdup("ERROR: Argument <contact-id> missing.");
			}
		}
		else {
			ret = safe_strdup("No chat selected.");
		}
	}
	else if( strncmp(cmd, "send ", 5)==0 )
	{
		if( sel_chat ) {
			char* arg1 = (char*)strstr(cmd, " ");
			if( arg1 && arg1[0] ) {
				mrmsg_t* msg = mrmsg_new();
					arg1++;
					msg->m_type = MR_MSG_TEXT;
					msg->m_text = strdup(arg1);
					if( mrchat_send_msg(sel_chat, msg) ) {
						ret = safe_strdup("Message sent.");
					}
					else {
						ret = safe_strdup("ERROR: Sending failed.");
					}
				mrmsg_unref(msg);
			}
			else {
				ret = safe_strdup("ERROR: No message text given.");
			}
		}
		else {
			ret = safe_strdup("No chat selected.");
		}
	}
	else if( strncmp(cmd, "sendimage", 8)==0 )
	{
		if( sel_chat ) {
			char* arg1 = (char*)strstr(cmd, " ");
			if( arg1 && arg1[0] ) {
				mrmsg_t* msg = mrmsg_new();
					arg1++;
					msg->m_type = MR_MSG_IMAGE;
					mrparam_set(msg->m_param, 'f', arg1);
					if( mrchat_send_msg(sel_chat, msg) ) {
						ret = safe_strdup("Image sent.");
					}
					else {
						ret = safe_strdup("ERROR: Sending failed.");
					}
				mrmsg_unref(msg);
			}
			else {
				ret = safe_strdup("ERROR: No message text given.");
			}
		}
		else {
			ret = safe_strdup("No chat selected.");
		}
	}
	else if( strncmp(cmd, "search ", 7)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			arg1++;
			carray* msglist = mrmailbox_search_msgs(mailbox, sel_chat? sel_chat->m_id : 0, arg1);
			if( msglist ) {
				log_msglist(mailbox, msglist);
				ret = mr_mprintf("%i messages found.", (int)carray_count(msglist));
				carray_free(msglist);
			}
		}
		else {
			ret = safe_strdup("ERROR: Argument <query> missing.");
		}
	}
	else if( strncmp(cmd, "draft", 5)==0 )
	{
		if( sel_chat ) {
			char* arg1 = (char*)strstr(cmd, " ");
			if( arg1 && arg1[0] ) {
				arg1++;
				mrchat_set_draft(sel_chat, arg1);
				ret = safe_strdup("Draft saved.");
			}
			else {
				mrchat_set_draft(sel_chat, NULL);
				ret = safe_strdup("Draft deleted.");
			}
		}
		else {
			ret = safe_strdup("No chat selected.");
		}
	}
	else if( strncmp(cmd, "showmedia", 9)==0 )
	{
		if( sel_chat ) {
			carray* images = mrmailbox_get_chat_media(mailbox, sel_chat->m_id, MR_MSG_IMAGE, MR_MSG_VIDEO);
			int i, icnt = carray_count(images);
			ret = mr_mprintf("%i images or videos: ", icnt);
			for( i = 0; i < icnt; i++ ) {
				char* temp = mr_mprintf("%s%sMsg #%i", i? ", ":"", ret, (int)(uintptr_t)carray_get(images, i));
				free(ret);
				ret = temp;
			}
			carray_free(images);
		}
		else {
			ret = safe_strdup("No chat selected.");
		}
	}
	else if( strncmp(cmd, "delchat ", 8)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			int chat_id = atoi(arg1);
			ret = mrmailbox_delete_chat(mailbox, chat_id)!=0? COMMAND_SUCCEEDED : COMMAND_FAILED;
		}
		else {
			ret = safe_strdup("ERROR: Argument <chat-id> missing.");
		}
	}


	/*******************************************************************************
	 * Message commands
	 ******************************************************************************/

	else if( strncmp(cmd, "msginfo ", 8)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			int id = atoi(arg1);
			ret = mrmailbox_get_msg_info(mailbox, id);
		}
		else {
			ret = safe_strdup("ERROR: Argument <message-id> missing.");
		}
	}
	else if( strncmp(cmd, "unseen", 6)==0 )
	{
		carray* msglist = mrmailbox_get_unseen_msgs(mailbox);
		if( msglist ) {
			log_msglist(mailbox, msglist);
			ret = mr_mprintf("%i unseen messages.", (int)carray_count(msglist));
			carray_free(msglist);
		}
	}
	else if( strncmp(cmd, "markseen ", 9)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			int id = atoi(arg1);
			ret = mrmailbox_markseen_msg(mailbox, id)? COMMAND_SUCCEEDED : COMMAND_FAILED;
		}
		else {
			ret = safe_strdup("ERROR: Argument <message-id> missing.");
		}
	}
	else if( strncmp(cmd, "delmsg ", 7)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			int id = atoi(arg1);
			ret = mrmailbox_delete_msg(mailbox, id)? COMMAND_SUCCEEDED : COMMAND_FAILED;
		}
		else {
			ret = safe_strdup("ERROR: Argument <message-id> missing.");
		}
	}


	/*******************************************************************************
	 * Contact commands
	 ******************************************************************************/

	else if( strncmp(cmd, "contacts", 8)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			arg1++;
		}
		carray* contacts = mrmailbox_get_known_contacts(mailbox, arg1);
		if( contacts ) {
			int i, cnt = carray_count(contacts);
			for( i = 0; i < cnt; i++ ) {
				mrcontact_t* contact = mrmailbox_get_contact(mailbox, (uint32_t)(uintptr_t)carray_get(contacts, i));
				if( contact ) {
					mrlog_info("Contact #%i: %s, %s", (int)contact->m_id,
						(contact->m_name&&contact->m_name[0])? contact->m_name : "<name unset>",
						(contact->m_addr&&contact->m_addr[0])? contact->m_addr : "<addr unset>");
					mrcontact_unref(contact);
				}
			}
			ret = mr_mprintf("%i contacts.", cnt);
			carray_free(contacts);
		}
		else {
			ret = COMMAND_FAILED;
		}
	}
	else if( strncmp(cmd, "adr", 3)==0 )
	{
		char *arg1 = (char*)strstr(cmd, " "), *arg2 = NULL;
		if( arg1 ) { arg1++; arg2 = strstr(arg1, ";"); }
		if( arg1 && arg2 ) {
			*arg2 = 0; arg2++;
			char* book = mr_mprintf("%s\n%s", arg1, arg2);
				mrmailbox_add_address_book(mailbox, book);
				ret = COMMAND_SUCCEEDED;
			free(book);
		}
		else {
			ret = safe_strdup("ERROR: Argument <name>;<addr> expected.");
		}
	}


	/*******************************************************************************
	 * Misc.
	 ******************************************************************************/

	else if( strncmp(cmd, "event", 5)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			int event = atoi(arg1);
			uintptr_t r = mailbox->m_cb(mailbox, event, 0, 0);
			ret = mr_mprintf("Sending event %i, received value %i.", (int)event, (int)r);
		}
		else {
			ret = safe_strdup("ERROR: Argument <id> missing.");
		}
	}
	else if( strncmp(cmd, "fileinfo", 8)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			arg1++;
			unsigned char* buf; size_t buf_bytes; uint32_t w, h;
			if( mr_read_file(arg1, (void**)&buf, &buf_bytes) ) {
				mr_get_filemeta(buf, buf_bytes, &w, &h);
				ret = mr_mprintf("width=%i, height=%i", (int)w, (int)h);
			}
			else {
				ret = safe_strdup("ERROR: Command failed.");
			}
		}
		else {
			ret = safe_strdup("ERROR: Argument <file> missing.");
		}
	}
	else
	{
		ret = COMMAND_UNKNOWN;
	}

cleanup:
	if( ret == COMMAND_SUCCEEDED ) {
		ret = safe_strdup("Command executed successfully.");
	}
	else if( ret == COMMAND_FAILED ) {
		ret = safe_strdup("ERROR: Command failed.");
	}
	else if( ret == COMMAND_UNKNOWN ) {
		ret = mr_mprintf("ERROR: Unknown command \"%s\", type ? for help.", cmd);
	}
	if( sel_chat ) { mrchat_unref(sel_chat); sel_chat = NULL; }
	return ret;
}


