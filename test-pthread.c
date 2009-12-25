#include <stdio.h>  
#include <stdlib.h>  
#include <errno.h>  
#include <pthread.h>  
  
#define GROUP_COUNT 100  
#define GROUP_SIZE 4   
  
typedef struct {  
    pthread_mutex_t mutex;  
    pthread_cond_t cond;  
    int index;  
} syn_obj_t;  
  
syn_obj_t syn_obj = {PTHREAD_MUTEX_INITIALIZER,   
    PTHREAD_COND_INITIALIZER, 0};  
  
typedef struct {  
    int flag;  
} elem_t;   
  
void* thread_routine(void* arg);
  
int main(int argc, char** argv)  
{  
    elem_t elems[GROUP_SIZE];  
    pthread_t pds[GROUP_SIZE];  
    int i;  
  
    printf("syn_obj.index = %d\n", syn_obj.index);  
  
    for (i = 0; i < GROUP_SIZE; i++) {  
        elems[i].flag = i;  
        if ( (pthread_create(&pds[i], NULL, thread_routine, &elems[i])) != 0 ) {  
            perror("pthread create");  
            exit(-1);  
        }  
    }  
  
    for (i = 0; i < GROUP_SIZE; i++) {  
        pthread_join(pds[i], NULL);  
    }
  
    pthread_mutex_destroy(&syn_obj.mutex);
    pthread_cond_destroy(&syn_obj.cond);
  
    printf("\nsyn_obj.index = %d\n", syn_obj.index);

    return 0;
}
  
void* thread_routine(void* arg)
{
    elem_t *elem = (elem_t *)arg;
    int i;

#if 0
   	printf("%d \n", elem->flag);
#else
    for (i = 0; i < GROUP_COUNT; i++) {
        pthread_mutex_lock(&syn_obj.mutex);
        while ( (syn_obj.index % GROUP_SIZE) != elem->flag ) {
            pthread_cond_wait(&syn_obj.cond, &syn_obj.mutex);
        }
        printf("%d", elem->flag);
        if ( 0 == (syn_obj.index+1) % GROUP_SIZE ) {
            printf("\t");
        }
        syn_obj.index++;
        pthread_cond_broadcast(&syn_obj.cond);
        // may be cause deadlock
        // pthread_cond_signal(&syn_obj.cond);
        pthread_mutex_unlock(&syn_obj.mutex);
        // sleep(1);
    }
#endif

    return NULL;
}
