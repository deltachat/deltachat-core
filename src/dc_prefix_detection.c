#include "dc_prefix_detection.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


const char* dc_find_subject_text_position(const char* subject) {
    dc_assert_non_null_pointer(subject);

    const char* subject_text_position = subject;
    const char prefix_separator = ':';
    const char* separator_position = strchr(subject_text_position, prefix_separator);

    while (separator_position != NULL
            && dc_is_prefix(subject_text_position, separator_position - subject_text_position)) {
        subject_text_position = dc_find_first_non_space_position(separator_position + 1);
        separator_position = strchr(subject_text_position, prefix_separator);
    }
    return subject_text_position;
}

static int dc_is_prefix(const char* string, ptrdiff_t string_bytes_count) {
    dc_assert_non_null_pointer(string);

    char* lower_case_string = dc_convert_prefix_letters_to_lower_case(string, string_bytes_count);
    const strings_array_bounds* prefixes = dc_get_prefixes();
    char** search_result = bsearch(&lower_case_string, prefixes->array, prefixes->entries_count,
            sizeof prefixes->array[0], dc_compare_strings);
    free(lower_case_string);
    return search_result != NULL;
}

static char* dc_convert_prefix_letters_to_lower_case(const char* string, ptrdiff_t string_bytes_count) {
    dc_assert_non_null_pointer(string);

    const int maximum_utf_8_bytes_count = 4;
    char* converted_string = dc_assuredly_allocate_zeroed_array(string_bytes_count * maximum_utf_8_bytes_count + 1, sizeof(char));
    int character_bytes_count;
    size_t j = 0;

    for (size_t i = 0; i < string_bytes_count; i += character_bytes_count) {
        character_bytes_count = dc_read_utf_8_character_bytes_count(string[i]);
        if (character_bytes_count == 1) {
            converted_string[j] = tolower(string[i]);
            j++;
        } else if (character_bytes_count > 1) {
            bytes_array_bounds* utf_8_bytes = dc_map_to_utf_8_lower_case_if_known(&string[i], character_bytes_count);
            memcpy(&converted_string[j], utf_8_bytes->array, utf_8_bytes->entries_count);
            j += utf_8_bytes->entries_count;
            free(utf_8_bytes);
        } else {
            printf("Conversion of prefix letters to lower case aborted due to invalid UTF-8 character.\n");
            break;
        }
    }
    return converted_string;
}

static int dc_read_utf_8_character_bytes_count(char first_character_byte) {
    if (!dc_is_bit_set(first_character_byte, CHAR_BIT - 1)) {
        return 1;
    }

    int leading_set_bits_count = 0;
    for (int i = CHAR_BIT - 1; dc_is_bit_set(first_character_byte, i); i--) {
        leading_set_bits_count++;
    }
    return leading_set_bits_count;
}

static int dc_is_bit_set(char byte, unsigned int bit_index) {
    return byte & (1 << bit_index);
}

static bytes_array_bounds* dc_map_to_utf_8_lower_case_if_known(const char* upper_case_character, int character_bytes_count) {
    dc_assert_non_null_pointer(upper_case_character);

    const bicameral_utf_8_letter* letter = dc_search_for_bicameral_letter(upper_case_character, character_bytes_count);
    bytes_array_bounds* utf_8_bytes = dc_assuredly_allocate_zeroed_array(1, sizeof(bytes_array_bounds));
    if (letter != NULL) {
        utf_8_bytes->array = letter->lower_case;
        utf_8_bytes->entries_count = strlen(letter->lower_case);
    } else {
        utf_8_bytes->array = upper_case_character;
        utf_8_bytes->entries_count = character_bytes_count;
    }
    return utf_8_bytes;
}

static const bicameral_utf_8_letter* dc_search_for_bicameral_letter(const char* upper_case_character, int character_bytes_count) {
    dc_assert_non_null_pointer(upper_case_character);

    bicameral_utf_8_letter letter = {
        .upper_case = dc_assuredly_allocate_zeroed_array(character_bytes_count + 1, sizeof(char))
    };
    memcpy(letter.upper_case, upper_case_character, character_bytes_count);

    const bicameral_utf_8_letters_array_bounds* letters = dc_get_prefix_letters();
    bicameral_utf_8_letter* search_result = bsearch(&letter, letters->array, letters->entries_count,
            sizeof letters->array[0], dc_compare_utf_8_letters_by_upper_case);
    free(letter.upper_case);
    return search_result;
}

static void* dc_assuredly_allocate_zeroed_array(size_t entries_count, size_t entry_bytes_count) {
    void* array = calloc(entries_count, entry_bytes_count);
    if (array == NULL) {
        dc_exit_with_error(FAILED_TO_ALLOCATE_MEMORY, "memory allocation failed");
    }
    return array;
}

static const bicameral_utf_8_letters_array_bounds* dc_get_prefix_letters() {
    static bicameral_utf_8_letter letters_array[] = {
        { .lower_case = "á", .upper_case = "Á" },
        { .lower_case = "í", .upper_case = "Í" },
        { .lower_case = "i", .upper_case = "İ" },
        { .lower_case = "α", .upper_case = "Α" },
        { .lower_case = "π", .upper_case = "Π" },
        { .lower_case = "ρ", .upper_case = "Ρ" },
        { .lower_case = "θ", .upper_case = "Θ" },
        { .lower_case = "σ", .upper_case = "Σ" },
        { .lower_case = "χ", .upper_case = "Χ" },
        { .lower_case = "ε", .upper_case = "Ε" },
        { .lower_case = "τ", .upper_case = "Τ" }
    };
    static bicameral_utf_8_letters_array_bounds letters = {
        .array = letters_array,
        .entries_count = sizeof letters_array / sizeof letters_array[0]
    };
    static int letters_sorted = 0;

    if (!letters_sorted) {
        qsort(letters.array, letters.entries_count, sizeof letters.array[0], dc_compare_utf_8_letters_by_upper_case);
        letters_sorted = 1;
    }
    return &letters;
}

static int dc_compare_utf_8_letters_by_upper_case(const void* left, const void* right) {
    dc_assert_non_null_pointer(left);
    dc_assert_non_null_pointer(right);
    const bicameral_utf_8_letter* left_letter = left;
    const bicameral_utf_8_letter* right_letter = right;

    dc_assert_non_null_pointer(left_letter->upper_case);
    dc_assert_non_null_pointer(right_letter->upper_case);
    return strcmp(left_letter->upper_case, right_letter->upper_case);
}

static const strings_array_bounds* dc_get_prefixes() {
    static char* prefixes_array[] = {
        "atb", "aw", "antwort", "antw", "bls", "doorst", "enc", "fs", "fw",
        "fwd", "i", "odp", "pd", "r", "re", "ref", "res", "rif", "rv", "sv",
        "svar", "tr", "trs", "továbbítás", "vb", "vl", "vs", "vá", "wg",
        "yml", "ynt", "ilt", "απ", "πρθ", "σχετ", "הועבר", "תגובה",
        "إعادة توجيه", "رد", "回复", "回覆", "轉寄", "转发"
    };
    static strings_array_bounds prefixes = {
        .array = prefixes_array,
        .entries_count = sizeof prefixes_array / sizeof prefixes_array[0]
    };
    static int prefixes_sorted = 0;

    if (!prefixes_sorted) {
        qsort(prefixes.array, prefixes.entries_count, sizeof prefixes.array[0], dc_compare_strings);
        prefixes_sorted = 1;
    }
    return &prefixes;
}

static int dc_compare_strings(const void* left, const void* right) {
    dc_assert_non_null_pointer(left);
    dc_assert_non_null_pointer(right);
    char* const* left_string_pointer = left;
    char* const* right_string_pointer = right;

    dc_assert_non_null_pointer(*left_string_pointer);
    dc_assert_non_null_pointer(*right_string_pointer);
    return strcmp(*left_string_pointer, *right_string_pointer);
}

static const char* dc_find_first_non_space_position(const char* string) {
    dc_assert_non_null_pointer(string);

    while (isspace(*string) && *string != '\0') {
        string++;
    }
    return string;
}

static void dc_assert_non_null_pointer(const void* pointer) {
    if (pointer == NULL) {
        dc_exit_with_error(ILLEGAL_NULL_POINTER, "a pointer was illegally NULL");
    }
}

static void dc_exit_with_error(const programming_error_code code, const char* message) {
    printf("Terminating because %s.\n", message);
    exit(code);
}

