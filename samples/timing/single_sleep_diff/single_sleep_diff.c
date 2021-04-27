#include <stdio.h>

int main(int argc, char** argv) {
    int i = 0;
    if (argv[1][0] == 0x41)
    {
        i = 1;
    }
    if(i==0) {
        sleep(2);
    } else {
        sleep(1);
    }
    printf("Hello\n");
    if(i==0) {
        sleep(1);
    } else {
        sleep(2);
    }
    printf("Goodbye\n");
    return 0;
}