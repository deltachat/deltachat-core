#include "dc_context.h"
#include "dc_mimeparser.h"
#include "dc_job.h"


dc_move_state_t dc_resolve_move_state(dc_context_t* context, const dc_msg_t* msg)
{
	dc_move_state_t res = dc_determine_next_move_state(context, msg);

	switch (res)
	{
		case DC_MOVE_STATE_MOVING:
			dc_job_add(context, DC_JOB_MOVE_MSG, msg->id, NULL, 0);
			dc_update_msg_move_state(context, msg->rfc724_mid, DC_MOVE_STATE_MOVING);
			break;

		case DC_MOVE_STATE_STAY:
			dc_update_msg_move_state(context, msg->rfc724_mid, DC_MOVE_STATE_STAY);
			break;

		default:
			break;
	}

	return res;
}


// Return the next move state for this message.
// Only call this function if the message is pending.
// This function works with the DB, does not perform any IMAP commands.
dc_move_state_t dc_determine_next_move_state(dc_context_t* context, const dc_msg_t* msg)
{
	dc_move_state_t res = DC_MOVE_STATE_UNDEFINED;
	int             last_dc_count = 0;

	if (msg==NULL || msg->move_state!=DC_MOVE_STATE_PENDING) {
		goto cleanup;
	}

	if (dc_sqlite3_get_config_int(context->sql, "mvbox_move", DC_MVBOX_MOVE_DEFAULT)==0) {
		goto cleanup;
	}

	if (!dc_is_inbox(context, msg->server_folder)
	 && !dc_is_sentbox(context, msg->server_folder)) {
		goto cleanup;
	}

	if (dc_is_mvbox(context, msg->server_folder)) {
		res = DC_MOVE_STATE_STAY;
		goto cleanup;
	}

	// having a message in SENTBOX or INBOX that is PENDING and moving is enabled

	#if 0 // to be continued ...
	while (1)
	{
		last_dc_count = msg->is_dc_message? (last_dc_count + 1) : 0;

		if (msg->in_reply_to==NULL || msg->in_reply_to[0]==0)
		{
            if (last_dc_count > 0) {
				return DC_MOVE_STATE_MOVING;
            }
            else {
				return DC_MOVE_STATE_STAY:
            }
		}

		newmsg
	}
	#endif

	res = msg->is_dc_message? DC_MOVE_STATE_MOVING : DC_MOVE_STATE_STAY;

cleanup:
	return res;
}
