#include <stdio.h>

int main(int argc, char** argv) {
    printf("Hello\n");
    int i=0;
    if(argv[1][0] == 'a') {
        while(i<5) {
            i += 1;
        }
    }
    printf("Goodbye\n");
    return 0;
}