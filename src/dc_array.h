#ifndef __DC_ARRAY_H__
#define __DC_ARRAY_H__
#ifdef __cplusplus
extern "C" {
#endif


/** the structure behind dc_array_t */
struct _dc_array
{
	/** @privatesection */

	uint32_t        magic;
	dc_context_t*   context;     /**< The context the array belongs to. May be NULL when NULL is given to dc_array_new(). */
	size_t          allocated;   /**< The number of allocated items. Initially ~ 200. */
	size_t          count;       /**< The number of used items. Initially 0. */
	int             type;
	uintptr_t*      array;       /**< The data items, can be used between data[0] and data[cnt-1]. Never NULL. */
};


struct _dc_location
{
	#define DC_ARRAY_LOCATIONS  1
	double   latitude;
	double   longitude;
	double   accuracy;
	time_t   timestamp;
	uint32_t msg_id;
};

dc_array_t*      dc_array_new                 (dc_context_t*, size_t initsize);
dc_array_t*      dc_array_new_typed           (dc_context_t*, int type, size_t initsize);
void             dc_array_empty               (dc_array_t*);
void             dc_array_free_ptr            (dc_array_t*);
dc_array_t*      dc_array_duplicate           (const dc_array_t*);
void             dc_array_sort_ids            (dc_array_t*);
void             dc_array_sort_strings        (dc_array_t*);
char*            dc_array_get_string          (const dc_array_t*, const char* sep);
char*            dc_arr_to_string             (const uint32_t* arr, int cnt);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __DC_ARRAY_H__ */
