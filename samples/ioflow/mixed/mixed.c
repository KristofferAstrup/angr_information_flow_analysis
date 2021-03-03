#include <stdio.h>
#include <stdbool.h> 

void logger_internal(char* str) {
    printf("%s\n", str);
}

void logger(char* str) {
    bool lowFirstChar = false;
    if(str[0] < 0) {
        lowFirstChar = true;
    }
    if(lowFirstChar) {
        logger_internal(str);
    }
}

int main(int argc, char** argv) {
    printf("Begin\n");
    if(argc != 3) {
        char* str = argv[1];
        logger(str);
    }
    printf("End\n");
}
