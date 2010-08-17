#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>

#define N 100  //设置最大的定时器个数

int i=0,t=1; //i代表定时器的个数；t表示时间，逐秒递增

struct Timer //Timer结构体，用来保存一个定时器的信息
{   
    int total_time;  //每隔total_time秒
    int left_time;   //还剩left_time秒
    int func;        //该定时器超时，要执行的代码的标志
}myTimer[N];    //定义Timer类型的数组，用来保存所有的定时器

void setTimer(int t,int f) //新建一个计时器
{   
    struct Timer a;
    a.total_time=t;
    a.left_time=t;
    a.func=f;
    myTimer[i++]=a;
}

void timeout()  //判断定时器是否超时，以及超时时所要执行的动作
{  
    printf("Time: %d\n",t++);
    int j;
    for(j=0;j<i;j++)
    {  
        if(myTimer[j].left_time!=0)
            myTimer[j].left_time--;
        else
        {   
            switch(myTimer[j].func){ //通过匹配myTimer[j].func，判断下一步选择哪种操作
            case 1:
                printf("------Timer 1: --Hello Aillo!\n");break;
            case 2:
                printf("------Timer 2: --Hello Jackie!\n");break;
            case 3:
                printf("------Timer 3: --Hello PiPi!\n");break;
            }
            myTimer[j].left_time=myTimer[j].total_time;     //循环计时
        }
    }
}

int main()  //测试函数，定义三个定时器
{   
    setTimer(3,1);
    setTimer(4,2);
    setTimer(5,3);
    signal(SIGALRM,timeout);  //接到SIGALRM信号，则执行timeout函数
    while(1)
    {  
        sleep(1);  //每隔一秒发送一个SIGALRM
        kill(getpid(),SIGALRM);
    }
    exit(0);
}
