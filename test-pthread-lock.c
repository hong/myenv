// g++ -o t t.c -lpthread
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

class CThreadQueue
{
public:
    CThreadQueue(int queueSize=1024):
        sizeQueue(queueSize),lput(0),lget(0),nFullThread(0),nEmptyThread(0),nData(0)
    {
        pthread_mutex_init(&mux,0);
        pthread_cond_init(&condGet,0);
        pthread_cond_init(&condPut,0);
        buffer=new void *[sizeQueue];
    }
    virtual ~CThreadQueue()
    {
        delete[] buffer;
    }
    void * getq()
    {
        void *data;
        pthread_mutex_lock(&mux);
        /*
         此处循环判断的原因如下：假设2个线程在getq阻塞，然后两者都被激活，而其中一个线程运行比较块，快速消耗了2个数据，另一个线程醒来的时候已经没有新数据可以消耗了。另一点，man pthread_cond_wait可以看到，该函数可以被信号中断返回，此时返回EINTR。为避免以上任何一点，都必须醒来后再次判断睡眠条件。更正：pthread_cond_wait是信号安全的系统调用，不会被信号中断。
        */
        while(lget==lput&&nData==0)
        {
            nEmptyThread++;
            pthread_cond_wait(&condGet,&mux);
            nEmptyThread--;     
        }

        data=buffer[lget++];
        nData--;
        if(lget==sizeQueue)
        {
            lget=0;
        }
        if(nFullThread) //必要时才进行signal操作，勿总是signal
        {
            pthread_cond_signal(&condPut);    
        }
        pthread_mutex_unlock(&mux);
        return data;
    }
    void putq(void *data)
    {
        pthread_mutex_lock(&mux);
        while(lput==lget&&nData)
        { 
            nFullThread++;
            pthread_cond_wait(&condPut,&mux);
            nFullThread--;
        }
        buffer[lput++]=data;
        nData++;
        if(lput==sizeQueue)
        {
            lput=0;
        }
        if(nEmptyThread) //必要时才进行signal操作，勿总是signal
        {
            pthread_cond_signal(&condGet);
        }
        pthread_mutex_unlock(&mux);
    }
private:
    pthread_mutex_t mux;
    pthread_cond_t condGet;
    pthread_cond_t condPut;

    void * * buffer;    //循环消息队列
    int sizeQueue;        //队列大小
    int lput;        //location put  放数据的指针偏移
    int lget;        //location get  取数据的指针偏移
    int nFullThread;    //队列满，阻塞在putq处的线程数
    int nEmptyThread;    //队列空，阻塞在getq处的线程数
    int nData;        //队列中的消息个数，主要用来判断队列空还是满
};

CThreadQueue queue;//使用的时候给出稍大的CThreadQueue初始化参数，可以减少进入内核态的操作。

void * produce(void * arg)
{
    int i=0;
    pthread_detach(pthread_self());
    while(i++<100)
    {
        queue.putq((void *)i);
    }
}

void *consume(void *arg)
{
    int data;
    while(1)
    {
        data=(int)(queue.getq());
        printf("data=%d\n",data);
    }
}

int main()
{    
    pthread_t pid;
    int i=0;

    while(i++<3)
        pthread_create(&pid,0,produce,0);
    i=0;
    while(i++<3)
        pthread_create(&pid,0,consume,0);
    sleep(5);

    return 0;
}
