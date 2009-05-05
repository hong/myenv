#include <stdio.h>

int main()
{
	int a=10, b=20; 
	int c=0;  

	asm("movl %1,%%eax; \
		 addl %2,%%eax; \
		 movl %%eax,%0;"
		 :"=m"(c)
		 :"r"(a), "r"(b)
		 :"%eax");

	printf("a+b=%d\n",c);

	return 0;
}
