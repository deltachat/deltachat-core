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


dc_move_state_t dc_determine_next_move_state(dc_context_t* context, const dc_msg_t* msg)
{
	// Return the next move state for this message.
	// Only call this function if the message is pending.
	// This function works with the DB, does not perform any IMAP commands.
	dc_move_state_t res = DC_MOVE_STATE_UNDEFINED;
	dc_msg_t*       newmsg = NULL;

	if (context==NULL || msg==NULL) {
		goto cleanup;
	}

	// TODO: where is a good place to check for user-disabled moving?
	if (dc_sqlite3_get_config_int(context->sql, "mvbox_move", DC_MVBOX_MOVE_DEFAULT)==0) {
		goto cleanup;
	}

	dc_log_info(context, 0, "[move] shall_move %s", msg->rfc724_mid);

	if (!dc_is_inbox(context, msg->server_folder)
	 && !dc_is_sentbox(context, msg->server_folder)) {
		dc_log_info(context, 0, "[move] %s neither in INBOX nor in SENTBOX", msg->rfc724_mid);
		goto cleanup;
	}

	if (msg->move_state!=DC_MOVE_STATE_PENDING) {
		dc_log_info(context, 0, "[move] %s is not PENDING, this should not happen", msg->rfc724_mid);
		goto cleanup;
	}

	if (dc_is_mvbox(context, msg->server_folder)) {
		dc_log_info(context, 0, "[move] %s is already in mvbox, next state is STAY", msg->rfc724_mid);
		res = DC_MOVE_STATE_STAY;
		goto cleanup;
	}

	// TODO: we should implement some protection against deadlocks here
	int last_dc_count = 0;
	while (1)
	{
		last_dc_count = msg->is_dc_message? (last_dc_count + 1) : 0;

		if (msg->in_reply_to==NULL || msg->in_reply_to[0]==0)
		{
			dc_log_info(context, 0, "[move] detected thread-start %s message", last_dc_count? "DC" : "CLEAR");
			if (last_dc_count > 0) {
				res = DC_MOVE_STATE_MOVING;
				goto cleanup;
			}
			else {
				res = DC_MOVE_STATE_STAY;
				goto cleanup;
			}
		}

		dc_msg_t* temp = dc_msg_new_load(context,
			dc_rfc724_mid_exists(context, msg->in_reply_to, NULL, NULL));
		dc_msg_unref(newmsg); // unref after consuming msg->in_reply_to above
		newmsg = temp;

		if (newmsg==NULL || newmsg->id==0)
		{
			dc_log_info(context, 0, "[move] failed to fetch from db: %s", msg->in_reply_to);
			// we don't have the parent message ... maybe because
			// it hasn't arrived (yet), was deleted or we failed to
			// scan/fetch it:
			if (last_dc_count >= 4) {
				dc_log_info(context, 0, "[move] no thread start found, bug last 4 messages were dc");
				res = DC_MOVE_STATE_MOVING;
				goto cleanup;
			}
			else {
				dc_log_info(context, 0, "[move] pending: missing parent, last_dc_count=%i", last_dc_count);
				res = DC_MOVE_STATE_PENDING;
				goto cleanup;
			}
		}
		else if (newmsg->move_state==DC_MOVE_STATE_MOVING)
		{
			dc_log_info(context, 0, "[move] parent was a moved message"); // and papa was rolling stone.
			res = DC_MOVE_STATE_MOVING;
			goto cleanup;
		}
		else
		{
			msg = newmsg;
		}
	}

cleanup:
	dc_msg_unref(newmsg);
	return res;
}
