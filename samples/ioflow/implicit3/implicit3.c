#include <stdio.h>

int printer(int argc, char** argv)
{
    char* str;
    if(argc == 1)
    {
        str = "first";
    }
    else if(argc == 2)
    {
        str = "second";
    }
    printf("%s\n", str);
}

int main(int argc, char** argv) {
    if(argc == 0 || argc > 2)
        return 1;
    printf("%s\n", "Begin");
    printer(argc, argv);
    printf("%s\n", "End");
}