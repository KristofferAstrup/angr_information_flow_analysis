#include <stdio.h>

int main(int argc, char** argv) {
    for(int e=0; e<10; e++)
    {
        printf("\n%s\n", "seq");
        for(int i=e*10; i<100; i++)
        {
            printf("%d, ", i);
            while(i==99 && argv[1][e] == i+e)
            {
                if(e != 5)
                    break;
                //Infinite
            }
        }
    }
    printf("\n%s\n", "End");
}