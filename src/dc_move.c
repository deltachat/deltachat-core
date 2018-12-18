#include "dc_context.h"


int dc_shall_move(dc_context_t* context, uint32_t msg_id)
{
	// TODO
	return 0;
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
