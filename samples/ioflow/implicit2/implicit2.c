#include <stdio.h>

int main(int argc, char** argv) {
    int i=0;
    while(i < argc)
    {
        printf("%d\n", i);
        i++;
    }
    printf("%d\n", i);
}