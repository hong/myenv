#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

/* insertion sort O(n2) */
void insert_sort(int array[], int length)
{
	int i, j, key;
	for (i = 1; i < length; i++)
	{
		key = array[i];
		// 把i之前大于array[i]的数据向后移动
		for (j = i - 1; j >= 0 && array[j] > key; j--)
		{
			array[j + 1] = array[j];
		}
		// 在合适位置安放当前元素
		array[j + 1] = key;
	}
}

/* bubble sort O(n2) */
void bubble_sort(int array[], int length)
{
	int i = 0, j = 0, t = 0;

	for (i = 0; i < length; i++)
	{
		for (j = i+1; j < length; j++)
		{
			if (array[i] > array[j])
			{
				t = array[i];
				array[i] = array[j];
				array[j] = t;
			}
		}
	}
}

/* selection sort O(n2) */
void select_sort(int array[], int length)
{
	int  x, y, index_of_min = 0, temp = 0;
  
	for(x = 0; x < length; x++)
	{
		index_of_min = x;
		for(y = x + 1; y < length; y++)
		{
			if(array[index_of_min]>array[y])
				index_of_min = y;
		}

		temp = array[x];
		array[x] = array[index_of_min];
		array[index_of_min] = temp;
	}
}

/* quick sort O(n log n) */
void quicksort(int p[], int start, int end)
{
	if (start < end)
	{
		int i = start, j = end - 1, t = 0;
		do
		{
			while(p[i]<p[end])
				i++;
			while(p[j]>=p[end])
				j--; //(4) 解决相等元素问题。

			if (i<j)
			{
				t = p[i];
				p[i] = p[j];
				p[j] = t;
			}
			else
			{
			   	//确定pivot的准确位置。
				t = p[i];
				p[i] = p[end];
				p[end] = t;
			}
		}
		while(i < j);
		//(3)至此完成了一趟快速排序得到：小于 pivot的数 | pivot | 大于等于pivot的数

		quicksort(p, start, i-1); //对小于pivot的数进行快速排序。
		quicksort(p, i+1, end); //对大于等于pivot的数进行快速排序。
		//(2).2 如果i到end时，即end前的所有元素都小于pivot，会发现，i+1>end了，即递归调用时会立刻返回，所以不会发生p[i]操作越界的现象，因为根本就没机会往下走。(2).3同理。
	}
}

/* shell sort O(n log n) */
void  shell_sort(int array[], int len)
{
	int t, h, i, j, op, temp;

	for (t=0; t < len; t++)
	{
		h = array[t];
		if (h > len/3)
			continue;
		for (i=h; i < len; i++)
		{
			temp=array[i];
			for (j=i-h; j>=0 && array[j]>temp; j-=h)
			{
				array[j+h] = array[j];
				op++;
			}
			array[j+h]=temp;
			op++;
		}
	} 
}

/* heap sort O(n log n) */

int main(int argc, char* argv[])
{
	int data[] = //{3, 6, 12, 1, 16, 32, 12};
				{49, 38, 65, 97, 76, 13, 27, 49, 55, 4};
	int i = 0, len = 0;

	len = sizeof(data)/sizeof(int);
	for (i = 0; i < len; i++)
		printf("%d, ", data[i]);
	printf(" len=%d\n", len);

	/* sort */
	//quicksort(data, 0, len-1);
	//insert_sort(data, len);
	shell_sort(data, len);

	for (i = 0; i < len; i++)
		printf("%d, ", data[i]);
	printf("\n");

	/* search */

	return 0;
}

int　search(int　array[],　int　n,　int　v)
{
　　　　int　left,　right,　middle;

　　　　left　=　0,　right　=　n　-　1;

　　　　while　(left　<=　right)
　　　　{
　　　　　　　　middle　=　(left　+　right)　/　2;
　　　　　　　　if　(array[middle]　>　v)
　　　　　　　　{
　　　　　　　　　　　　right　=　middle　-　1;
　　　　　　　　}
　　　　　　　　else　if　(array[middle]　<　v)
　　　　　　　　{
　　　　　　　　　　　　left　=　middle　+　1;
　　　　　　　　}
　　　　　　　　else
　　　　　　　　{
　　　　　　　　　　　　return　middle;
　　　　　　　　}
　　　　}

　　　　return　-1;
}

int　search_recurse(int　array[],　int　low,　int　high,　int　v)
{
　　　　int　middle;

　　　　middle　=　(low　+　high)　/　2;

　　　　if　(low　<　high)
　　　　{
　　　　　　　　if　(array[middle]　>　v)
　　　　　　　　{
　　　　　　　　　　　　return　search_recurse(array,　low,　middle,　v);
　　　　　　　　}
　　　　　　　　else　if　(array[middle]　<　v)
　　　　　　　　{
　　　　　　　　　　　　return　search_recurse(array,　middle　+　1,　high,　v);
　　　　　　　　}
　　　　　　　　else
　　　　　　　　{
　　　　　　　　　　　　return　middle;
　　　　　　　　}
　　　　}
　　　　else　if　(low　==　high)
　　　　{
　　　　　　　　if　(array[middle]　==　v)
　　　　　　　　{
　　　　　　　　　　　　return　middle;
　　　　　　　　}
　　　　　　　　else
　　　　　　　　{
　　　　　　　　　　　　return　-1;
　　　　　　　　}

　　　　}
　　　　else
　　　　{
　　　　　　　　return　-1;
　　　　}

　　　　return　-1;
}

int　main()
{
　　　　int　array[]　=　{0,　1,　2,　3,　4,　5,　6,　7,　13,　19};

　　　　int　m　=　search(array,　sizeof(array)/sizeof(array[0]),　13);

　　　　printf("m　=　%d\n",　m);

　　　　m　=　search_recurse(array,　0,　sizeof(array)/sizeof(array[0]),　13);

　　　　printf("m　=　%d\n",　m);

　　　　return　0;
}
