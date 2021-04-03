#include <stdio.h>

int main(int argc, char** argv) {
    printf("Hello\n");
    if(argv[1][0] == 'a') {
        for(int i=1; i<=3; i++) {
            sleep(i);
        }
    } else {
        sleep(6);   
    }
    printf("Goodbye\n");
    return 0;
}