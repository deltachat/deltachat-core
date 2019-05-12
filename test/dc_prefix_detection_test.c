#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>

#define malloc test_malloc
#define calloc test_calloc
#define realloc test_realloc
#define free test_free

/*
Include source instead of header file to
  * replace allocation functions with Cmocka memory checking functions
  * test static functions as well
*/
#include "../src/dc_prefix_detection.c"


static void is_bit_set_true_for_all_bits_set(void** state)
{
	// Arrange
	char eight_bits_set_byte = 0xFF;

	// Act / Assert
	for (int i = 0; i < 8; i++) {
		assert_true(dc_is_bit_set(eight_bits_set_byte, i));
	}
}

static void is_bit_set_true_for_one_bit_set(void** state)
{
	// Arrange
	char fifth_bit_set_byte = 0x10;

	// Act / Assert
	assert_true(dc_is_bit_set(fifth_bit_set_byte, 4));
}

static void is_bit_set_false_for_all_bits_unset(void** state)
{
	// Arrange
	char no_bits_set_byte = 0;

	// Act / Assert
	for (int i = 0; i < 8; i++) {
		assert_false(dc_is_bit_set(no_bits_set_byte, i));
	}
}

static void is_bit_set_false_for_one_bit_unset(void** state)
{
	// Arrange
	char fifth_bit_unset_byte = 0xEF;

	// Act / Assert
	assert_false(dc_is_bit_set(fifth_bit_unset_byte, 4));
}

static void read_utf_8_character_bytes_count_correctly(void** state)
{
	// Arrange
	const char* characters[] = {
		"Α", "Π", "ה"
	};
	const size_t characters_count = sizeof characters / sizeof characters[0];

	for (size_t i = 0; i < characters_count; i++) {
		// Act
		int set_bits_count = dc_read_utf_8_character_bytes_count(characters[i][0]);

		// Assert
		assert_int_equal(set_bits_count, 2);
	}
}

static void convert_prefix_letters_to_lower_case_correctly(void** state)
{
	// Arrange
	const char* prefixes[] = {
		"ATB", "AW", "Antwort", "Antw", "BLS", "Doorst", "ENC", "FS", "FW",
		"FWD", "I", "Odp", "PD", "R", "RE", "Re", "REF", "RES", "RIF", "RV",
		"SV", "Svar", "TR", "TRS", "Továbbítás", "VB", "VL", "VS", "Vá", "WG",
		"YML", "YNT", "İLT", "ΑΠ", "ΠΡΘ", "ΣΧΕΤ", "Σχετ", "הועבר", "תגובה",
		"إعادة توجيه", "رد", "回复", "回覆", "轉寄", "转发"
	};
	const size_t prefixes_count = sizeof prefixes / sizeof prefixes[0];
	const char* expected[] = {
		"atb", "aw", "antwort", "antw", "bls", "doorst", "enc", "fs", "fw",
		"fwd", "i", "odp", "pd", "r", "re", "re", "ref", "res", "rif", "rv",
		"sv", "svar", "tr", "trs", "továbbítás", "vb", "vl", "vs", "vá", "wg",
		"yml", "ynt", "ilt", "απ", "πρθ", "σχετ", "σχετ", "הועבר", "תגובה",
		"إعادة توجيه", "رد", "回复", "回覆", "轉寄", "转发"
	};

	for (size_t i = 0; i < prefixes_count; i++) {
		// Act
		char* lower_case_prefix = dc_convert_prefix_letters_to_lower_case(prefixes[i], strlen(prefixes[i]));

		// Assert
		assert_string_equal(lower_case_prefix, expected[i]);
		free(lower_case_prefix);
	}
}

static void get_prefixes_returns_more_than_one_entry(void** state)
{
	// Arrange / Act
	const strings_array_bounds* prefixes = dc_get_prefixes();

	// Assert
	assert_true(prefixes->entries_count > 1);
}

static void get_prefixes_has_sorted_entries(void** state)
{
	// Arrange / Act
	const strings_array_bounds* prefixes = dc_get_prefixes();

	// Assert
	for (size_t i = 1; i < prefixes->entries_count; i++) {
		assert_true(strcmp(prefixes->array[i - 1], prefixes->array[i]) <= 0);
	}
}

static void get_prefixes_has_unique_entries(void** state)
{
	// Arrange / Act
	const strings_array_bounds* prefixes = dc_get_prefixes();

	// Assert
	for (size_t i = 1; i < prefixes->entries_count; i++) {
		assert_true(strcmp(prefixes->array[i - 1], prefixes->array[i]) != 0);
	}
}

static void is_prefix_true_for_prefixes_case_insensitively(void** state)
{
	// Arrange
	const char* prefixes[] = {
		"Re", "RE", "fwd", "Vá", "İLT", "ΑΠ", "הועבר", "رد", "回复"
	};
	const size_t prefixes_count = sizeof prefixes / sizeof prefixes[0];

	// Act / Assert
	for (size_t i = 0; i < prefixes_count; i++) {
		assert_true(dc_is_prefix(prefixes[i], strlen(prefixes[i])));
	}
}

static void is_prefix_false_for_non_prefixes(void** state)
{
	// Arrange
	const char* prefixes[] = {
		"", "Hey", "NEW", "Rezept", "Help us protect you", "Shop", "25.01.2010"
	};
	const size_t prefixes_count = sizeof prefixes / sizeof prefixes[0];

	// Act / Assert
	for (size_t i = 0; i < prefixes_count; i++) {
		assert_false(dc_is_prefix(prefixes[i], strlen(prefixes[i])));
	}
}

static void find_subject_text_position_for_chains_of_prefixes(void** state)
{
	// Arrange
	const char* subjects[] = {
		"Re: English prefix", "Fwd: RE: re: FW: English prefixes",
		"Antw: Odp: Vá: PD:Svar: İLT: International prefixes",
		"ΣΧΕΤ: Non-Latin alphabet prefix",
		"回覆: ΑΠ: إعادة توجيه: Σχετ:תגובה: 转发: Non-Latin alphabet prefixes",
		"Továbbítás: BLS: رد: RIF:Antwort: 回复: Mixed alphabet prefixes"
	};
	const size_t subjects_count = sizeof subjects / sizeof subjects[0];
	const char* expected[] = {
		"English prefix", "English prefixes", "International prefixes",
		"Non-Latin alphabet prefix", "Non-Latin alphabet prefixes",
		"Mixed alphabet prefixes"
	};

	for (size_t i = 0; i < subjects_count; i++) {
		// Act
		const char* pure_subject = dc_find_subject_text_position(NULL, subjects[i]);

		// Assert
		assert_non_null(pure_subject);
		assert_string_equal(pure_subject, expected[i]);
	}
}

static void find_subject_text_position_returns_input_for_non_prefixes(void** state)
{
	// Arrange
	const char* subjects[] = {
		"Hello: Single word", "Help us protect you: Sentence",
		"Re availability: Prefix separated by space only",
		"NEW: 10.03.2018: Non-prefix and date", "Hey:) How are you?",
		":D", "Funny:D", "Streaming: Show: Edition: Ultimate"
	};
	const size_t subjects_count = sizeof subjects / sizeof subjects[0];

	for (size_t i = 0; i < subjects_count; i++) {
		// Act
		const char* subject = dc_find_subject_text_position(NULL, subjects[i]);

		// Assert
		assert_string_equal(subject, subjects[i]);
	}
}

static void find_subject_text_position_starts_at_first_non_prefix(void** state)
{
	// Arrange
	const char* subjects[] = {
		"Hello: תגובה: Non-prefix, prefix",
		"I: Help us protect you: Prefix, non-prefix",
		"Re Antw: availability: Prefix separated by space only",
		"SV: WG: ΠΡΘ: NEW: 10.03.2018: Prefixes, non-prefixes",
		"FW: :D", ":D FW: Haha", "Re: Hey:) How are you?",
		"FYI: Save the date: Fwd: TRS: Non-prefixes, prefixes",
		"ΠΡΘ: Streaming: WG: Show: Edition: Ultimate",
	};
	const size_t subjects_count = sizeof subjects / sizeof subjects[0];
	const char* expected[] = {
		"Hello: תגובה: Non-prefix, prefix",
		"Help us protect you: Prefix, non-prefix",
		"Re Antw: availability: Prefix separated by space only",
		"NEW: 10.03.2018: Prefixes, non-prefixes",
		":D", ":D FW: Haha", "Hey:) How are you?",
		"FYI: Save the date: Fwd: TRS: Non-prefixes, prefixes",
		"Streaming: WG: Show: Edition: Ultimate",
	};

	for (size_t i = 0; i < subjects_count; i++) {
		// Act
		const char* subject = dc_find_subject_text_position(NULL, subjects[i]);

		// Assert
		assert_string_equal(subject, expected[i]);
	}
}

// Mock logging functions
void dc_log_warning(dc_context_t* context, int data1, const char* msg, ...)
{
	printf("Warning logged: ");
	va_list variable_arguments;
	va_start(variable_arguments, msg);
	vprintf(msg, variable_arguments);
	va_end(variable_arguments);
}

void dc_log_error(dc_context_t* context, int data1, const char* msg, ...)
{
	printf("Error logged: ");
	va_list variable_arguments;
	va_start(variable_arguments, msg);
	vprintf(msg, variable_arguments);
	va_end(variable_arguments);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(is_bit_set_true_for_all_bits_set),
		cmocka_unit_test(is_bit_set_true_for_one_bit_set),
		cmocka_unit_test(is_bit_set_false_for_all_bits_unset),
		cmocka_unit_test(is_bit_set_false_for_one_bit_unset),
		cmocka_unit_test(read_utf_8_character_bytes_count_correctly),
		cmocka_unit_test(convert_prefix_letters_to_lower_case_correctly),
		cmocka_unit_test(get_prefixes_returns_more_than_one_entry),
		cmocka_unit_test(get_prefixes_has_sorted_entries),
		cmocka_unit_test(get_prefixes_has_unique_entries),
		cmocka_unit_test(is_prefix_true_for_prefixes_case_insensitively),
		cmocka_unit_test(is_prefix_false_for_non_prefixes),
		cmocka_unit_test(find_subject_text_position_for_chains_of_prefixes),
		cmocka_unit_test(find_subject_text_position_returns_input_for_non_prefixes),
		cmocka_unit_test(find_subject_text_position_starts_at_first_non_prefix)
	};
	return cmocka_run_group_tests_name("dc_prefix_detection", tests, NULL, NULL);
}

