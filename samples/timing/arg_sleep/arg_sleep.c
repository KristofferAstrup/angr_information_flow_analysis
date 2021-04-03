#include <stdio.h>

int main(int argc, char** argv) {
    printf("Hello\n");
    if(argv[1][0] > 64) {
        sleep(argv[1][0] - 64);
    }
    printf("Goodbye\n");
    return 0;
}