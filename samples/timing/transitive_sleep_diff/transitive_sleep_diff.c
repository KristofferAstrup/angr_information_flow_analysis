#include <stdio.h>

int main(int argc, char** argv) {
    int t = 0;
    if(argv[1][0] == 'a') {
        t = 1;
    }
    if(t == 1) {
        sleep(10);   
    }
    printf("Goodbye\n");
    while(0 == 0) {

    }
    return 0;
}