#include <stdio.h>

int main(int argc, char** argv) {
    printf("%s\n", "nodanger");

    if(argc != 2) {
        char* str = argv[1];
        printf("%s\n", str);
    }
}