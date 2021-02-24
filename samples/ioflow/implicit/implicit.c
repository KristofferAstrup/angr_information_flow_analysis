#include <stdio.h>

int main(int argc, char** argv) {
    char* str = "lowcontext";
    if(argv[1][0] < 0)
    {
    	str = "highcontext";
    }
    printf("%s\n", str);
}
