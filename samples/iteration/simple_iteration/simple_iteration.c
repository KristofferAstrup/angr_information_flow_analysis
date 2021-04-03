#include <stdio.h>

int main(int argc, char** argv) {
    int i=0;
    while(argv[1][0] == 'a') {
        if(i==10) {
            printf("Break");
            break;
        }
        i++;
    }
    printf("Hello");
    return 0;
}