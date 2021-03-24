#include <stdio.h>

int main(int argc, char** argv) {
    printf("%s\n", "Start");
    for(int e=0; e<4; e++)
    {
        for(int i=e; i<4; i++)
        {
            while(i==3 && argv[1][e] == 64+i+e)
            {
                if(e != 2)
                    break;
                //Infinite
            }
        }
    }
    printf("%s\n", "End");
}