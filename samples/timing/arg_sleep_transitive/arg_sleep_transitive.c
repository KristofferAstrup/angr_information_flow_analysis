#include <stdio.h>

int main(int argc, char** argv) {
    printf("Hello\n");

    if(argv[1][0] > 65) {
        argv[1][0] = 'A';
    }
    else
    {
        argv[1][0] = 'B';
    }

    char x = '!';
    if( argv[1][0] == 'A') {
        x = 'A';
    } 
    else if( argv[1][0] == 'B') {
        x = 'B';
    }

    if(argv[1][0] > 'A') {
        printf("%c",x);
    }
    else
    {
        printf("%c",x);
    }

    printf("Goodbye\n");
    return 0;
}