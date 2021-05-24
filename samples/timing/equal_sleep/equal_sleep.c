#include <stdio.h>

int main(int argc, char** argv) {
    printf("Hello\n");
    if(argv[1][0] == 'a') {
        for(int i=0; i<3; i++) {
            sleep(1);
        }
    } else {
        sleep(3);   
    }
    printf("Goodbye\n");
    return 0;
}