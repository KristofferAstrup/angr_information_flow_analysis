#include <stdio.h>

int main(int argc, char** argv) {
    if(argv[1][0] > 65) {
        sleep(5);
        printf("HEJ");
        fflush(stdout);
    }
    else
    {
        printf("HEJ");
        fflush(stdout);
        sleep(5);
    }
    while(0==0){}
    return 0;
}