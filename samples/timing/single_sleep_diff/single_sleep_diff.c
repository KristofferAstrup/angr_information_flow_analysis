#include <stdio.h>

int main(int argc, char** argv) {
    printf("Hello\n");
    int i = argv[1][0] % 2;
    if(i==0) {
        sleep(2);
    } else {
        sleep(1);   
    }
    printf("Goodbye\n");
    if(i==0) {
        sleep(1);
    } else {
        sleep(2);   
    }
    return 0;
}