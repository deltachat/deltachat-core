#include "dc_context.h"
#include "dc_mimeparser.h"


int dc_shall_move(dc_context_t* context, const dc_mimeparser_t* parser, uint32_t msg_id)
{
	return parser->is_send_by_messenger;
}


/*
 * Move a message identified by UID from INBOX to MVBOX.
 * Optionally, messages are also markes as read,
 * which is useful for self-sended messages and for MDNs.
 */
void dc_schedule_move(dc_context_t* context, uint32_t server_uid, int markread)
{
	// TODO
}
