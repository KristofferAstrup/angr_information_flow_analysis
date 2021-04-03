#include <stdio.h>

int main(int argc, char** argv) {
    printf("Hello\n");
    if(argv[1][0] == 65) {
        sleep(argv[1][0] - 60);
    }
    else
    {
        sleep(5);
    }
    printf("Goodbye\n");
    return 0;
}