#include <stdio.h>
#include <stdbool.h> 

int main(int argc, char** argv) {
    bool b = false;
    if(!b)
    {
        b = true;
    }
    if(b)
    {
        printf("hello");
    }
    if(argc == 2)
    {
        b = false;
    }
}