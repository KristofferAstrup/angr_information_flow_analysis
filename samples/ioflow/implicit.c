#include <stdio.h>

int main(int argc, char** argv) {
    if(argc != 2) {
        return 0;
    }
    char* str = argv[1];
    if(str[0] < 0)
    {
        printf("%s\n", "wow");
    }
}