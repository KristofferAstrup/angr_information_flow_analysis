#include <stdio.h>

int main(int argc, char** argv) {
    printf("Hello\n");
    if(argv[1][0] == 'a') {
        sleep(10);   
    }
    printf("Goodbye\n");
    return 0;
}