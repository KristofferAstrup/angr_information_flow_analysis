#include <stdio.h>

void printer(int argc)
{
    char* str = "one";
    if(argc == 2)
    {
        str = "two";
    }
    else if(argc >= 3)
    {
        str = "three or more";
    }
    printf("%s\n", str);
}

int main(int argc, char** argv) {
    printer(argc);
}
