#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    if(argc != 4) {
        printf("Four arguments expected.\n");
        return 1;
    }
    char x = argv[1][0];
    char y = argv[2][0];
    char z = argv[3][0];
    if(x - y == z) {
        printf("Perfect!\n");
        return 0;
    }
    return 0;
}