#include <stdio.h>

int main(int argc, char** argv) {
    if(argv[1][0] > 65) {
        sleep(5);
        printf("HEJ");
    }
    else
    {
        printf("HEJ");
        sleep(5);
    }
    return 0;
}