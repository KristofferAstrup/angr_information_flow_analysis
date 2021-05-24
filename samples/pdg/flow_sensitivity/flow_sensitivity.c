#include <stdio.h>

int main(int argc, char** argv) {
    char* str = "lowcontext";
    if(argv[1][0] < 0)
    {
    	str = "highcontext";
    }
    str = ""; //Because of flow-sensitivity, this removes insecure flow through str
    printf("%s\n", str);
}
