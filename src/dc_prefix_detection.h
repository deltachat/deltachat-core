#ifndef __DC_PREFIX_DETECTION_H__
#define __DC_PREFIX_DETECTION_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

typedef struct {
    char* lower_case;
    char* upper_case;
} bicameral_utf_8_letter;

typedef struct {
    bicameral_utf_8_letter* array;
    size_t entries_count;
} bicameral_utf_8_letters_array_bounds;

typedef struct {
    char** array;
    size_t entries_count;
} strings_array_bounds;

typedef struct {
    const char* array;
    size_t entries_count;
} bytes_array_bounds;

typedef enum {
    FAILED_TO_ALLOCATE_MEMORY = 60,
    ILLEGAL_NULL_POINTER
} programming_error_code;


/**
 * Skips known subject prefixes and returns a pointer to the actual subject
 * text.
 *
 * @param subject
 *      Null-terminated subject string. The program is aborted if it is a null
 *      pointer.
 * @return
 *      Pointer into the given string at the position after detected prefixes.
 */
const char* dc_find_subject_text_position(const char* subject);

/**
 * The program is aborted if the given string is a null pointer.
 */
int dc_is_prefix(const char* string, ptrdiff_t string_bytes_count);

/**
 * Returns a newly allocated string which must be freed by the caller.
 *
 * The program is aborted if the given string is a null pointer.
 */
char* dc_convert_prefix_letters_to_lower_case(const char* string, ptrdiff_t string_bytes_count);

int dc_read_utf_8_character_bytes_count(char first_character_byte);

int dc_is_bit_set(char byte, unsigned int bit_index);

/**
 * Returns a newly allocated structure which must be freed by the caller. The
 * contained array must not be freed.
 *
 * The program is aborted if the given byte array is a null pointer.
 */
bytes_array_bounds* dc_map_to_utf_8_lower_case_if_known(const char* upper_case_character, int character_bytes_count);

/**
 * The program is aborted if the given byte array is a null pointer.
 */
const bicameral_utf_8_letter* dc_search_for_bicameral_letter(const char* upper_case_character, int character_bytes_count);

void* dc_assuredly_allocate_zeroed_array(size_t entries_count, size_t entry_bytes_count);

/**
 * Returns the upper and lower case variants of non-ASCII characters in the
 * known prefixes.
 * The list is fixed at compile time and new entries can be simply appended
 * as the function sorts it by upper case version upon first call.
 */
const bicameral_utf_8_letters_array_bounds* dc_get_prefix_letters();

/**
 * The program is aborted if any of the given letter structure pointers or the
 * contained upper case character arrays is a null pointer.
 */
int dc_compare_utf_8_letters_by_upper_case(const void* left, const void* right);

/**
 * Returns a list of the known subject prefixes.
 * The list is fixed at compile time and new entries can be simply appended
 * as the function sorts it upon first call.
 *
 * If new entries contain non-ASCII characters, their upper and lower case
 * variants must be registered in `dc_get_prefix_letters`.
 */
const strings_array_bounds* dc_get_prefixes();

/**
 * The program is aborted if any of the given string pointers or strings is a
 * null pointer.
 */
int dc_compare_strings(const void* left, const void* right);

/**
 * The program is aborted if the given string is a null pointer.
 */
const char* dc_find_first_non_space_position(const char* string);

/**
 * The program is aborted if the given pointer is a null pointer.
 */
void dc_assert_non_null_pointer(const void* pointer);

void dc_exit_with_error(const programming_error_code code, const char* message);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __DC_PREFIX_DETECTION_H__ */
