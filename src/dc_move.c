#include "dc_context.h"
#include "dc_mimeparser.h"


int dc_shall_move(dc_context_t*          context,
                  const char*            folder,
                  const dc_mimeparser_t* parser,
                  uint32_t               msg_id)
{
	int shall_move = 0;

	if (!dc_is_inbox(context, folder)) {
		goto cleanup;
	}

	if (dc_sqlite3_get_config_int(context->sql, "mvbox_move", DC_MVBOX_MOVE_DEFAULT)==0) {
		goto cleanup;
	}

	shall_move = parser->is_send_by_messenger;

cleanup:
	return shall_move;
}
