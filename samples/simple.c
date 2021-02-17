#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    if(argc != 4) {
        printf("Four arguments expected.\n");
        return 1;
    }
    int x = atoi(argv[1]);
    int y = atoi(argv[2]);
    int z = atoi(argv[3]);
    if(z != 0 && x * y == z && z - (x*2) == y) {
        printf("Perfect!\n");
        return 0;
    }
    return 0;
}