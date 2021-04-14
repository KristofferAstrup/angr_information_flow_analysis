#include <stdio.h>

int main(int argc, char** argv) {
    int t = 0;
    if(argv[1][0] > 60) {
        t = 1;
    }
    if(t > 1) {
        printf("%s\n", "!");
    }
}