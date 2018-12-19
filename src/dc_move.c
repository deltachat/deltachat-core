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

	if (dc_get_config(context, "mvbox_enabled")==0) {
		goto cleanup;
	}

	shall_move = parser->is_send_by_messenger;

cleanup:
	return shall_move;
}
