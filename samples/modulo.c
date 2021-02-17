#include <stdio.h>

int main(int argc, char** argv) {
    if(argc != 2) {
        printf("Two arguments expected.\n");
        return 1;
    }
    int n = atoi(argv[1]);
    int c = 0;
    while(n != 0)
    {
        n = (n + 2) % 100000;
        c++;
    }
    if(c % 10000 == 1)
    {
        printf("The lucky number!");
        return 0;
    }
    return 0;
}