#include <stdio.h>
#include <syscall.h>
#include <stdlib.h>

int main(int argc, char* argv[])
{
	int num[4];
	int fibo, maximus;
	for(int i=1; i<argc; i++){
		num[i-1] = atoi(argv[i]);
	}
	fibo = fibonacci(num[0]);
	maximus = max_of_four_int(num[0],num[1],num[2],num[3]);
	printf("%d %d\n",fibo,maximus);
	return 0;
}
