#ifndef __DC_JOBTHREAD_H__
#define __DC_JOBTHREAD_H__
#ifdef __cplusplus
extern "C" {
#endif


typedef struct _dc_jobthread dc_jobthread_t;


struct _dc_jobthread
{
	dc_context_t*    context;
	char*            name;
	char*            folder_config_name;

	struct _dc_imap* imap;

	pthread_mutex_t  mutex;

	pthread_cond_t   idle_cond;
	int              idle_condflag;

	int              jobs_needed;
	int              suspended;
	int              using_handle;

};


void dc_jobthread_init           (dc_jobthread_t*, dc_context_t* context, const char* name,
                                  const char* folder_config_name);
void dc_jobthread_exit           (dc_jobthread_t*);
void dc_jobthread_suspend        (dc_jobthread_t*, int suspend);

void dc_jobthread_fetch          (dc_jobthread_t*, int use_network);
void dc_jobthread_idle           (dc_jobthread_t*, int use_network);
void dc_jobthread_interrupt_idle (dc_jobthread_t*);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __DC_JOBTHREAD_H__ */

