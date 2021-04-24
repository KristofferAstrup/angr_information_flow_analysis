#include <stdio.h>

int printer(int argc, char** argv)
{
    char* str = "first";
    if(argc == 2)
    {
        str = "second";
    }
    else if(argc >= 3)
    {
        str = "third or more";
    }
    printf("%s\n", str);
}

int main(int argc, char** argv) {
    printf("%s\n", "Begin");
    printer(argc, argv);
    printf("%s\n", "End");
}