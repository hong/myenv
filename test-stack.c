#include <stdio.h>

int func(int a)
{
    int i = 9;
    *(&i+2) = *(&i+2)+7;
    return i;
}

int main()
{
    int i = 2;
    func(i);
    i = 1;
    printf("i=%d\n", i);
    return 0;
}
