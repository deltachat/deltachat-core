#ifndef __DC_STRBUILDER_H__
#define __DC_STRBUILDER_H__
#ifdef __cplusplus
extern "C" {
#endif


typedef struct _dc_strbuilder dc_strbuilder_t;


struct _dc_strbuilder
{
	char* buf;
	int   allocated;
	int   free;
	char* eos;
};


void  dc_strbuilder_init    (dc_strbuilder_t*, int init_bytes);
char* dc_strbuilder_cat     (dc_strbuilder_t*, const char* text);
void  dc_strbuilder_catf    (dc_strbuilder_t*, const char* format, ...);
void  dc_strbuilder_empty   (dc_strbuilder_t*);


#ifdef __cplusplus
} // /extern "C"
#endif
#endif // __DC_STRBUILDER_H__

