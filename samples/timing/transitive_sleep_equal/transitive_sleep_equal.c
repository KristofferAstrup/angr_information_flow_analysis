#include <stdio.h>

int add(int* i, char* str) {
    if(*i == 1) {
        *i += str[0];
    }
}

int main(int argc, char** argv) {
    int t = argv[1][0]%2 == 1;
    printf("Hello\n");
    add(&t, argv[1]);
    t = t%2;
    sleep(t+1);
    printf("Goodbye\n");
    while(t == 0) {
    }
    return 0;
}