#include <stdio.h>
#include <time.h>
#include <stdlib.h>
void main(int argc, char** argv){
  // printf("%d\n",argc);
  srand(atoi(argv[1]));

  printf("%p\n",rand() & 0xFFFFF000);
}
