#include "dc_context.h"
#include "dc_mimeparser.h"
#include "dc_job.h"


void dc_do_heuristics_moves(dc_context_t* context, const char* folder, uint32_t msg_id)
{
	// for already seen messages, folder may be different from msg->folder
	dc_msg_t*     msg = NULL;
	sqlite3_stmt* stmt = NULL;

	if (dc_sqlite3_get_config_int(context->sql, "mvbox_move", DC_MVBOX_MOVE_DEFAULT)==0) {
		goto cleanup;
	}

	if (!dc_is_inbox(context, folder) && !dc_is_sentbox(context, folder)) {
		goto cleanup;
	}

	msg = dc_msg_new_load(context, msg_id);

	if (dc_is_mvbox(context, folder)) {
		dc_update_msg_move_state(context, msg->rfc724_mid, DC_MOVE_STATE_STAY);
		goto cleanup;
	}

	if (msg->is_dc_message /*1=dc message, 2=reply to dc message*/) {
		dc_job_add(context, DC_JOB_MOVE_MSG, msg->id, NULL, 0);
		dc_update_msg_move_state(context, msg->rfc724_mid, DC_MOVE_STATE_MOVING);
	}

cleanup:
	sqlite3_finalize(stmt);
	dc_msg_unref(msg);
}
