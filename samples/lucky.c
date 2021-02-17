#include <stdio.h>

int main() {
    int n;
    printf("Enter size\n");
    scanf("%d", &n);
    int c = 0;
    while(n != 0)
    {
        n = n + 2;
        c++;
    }
    if(c - 10000 == 1)
    {
        printf("The lucky number!");
        return 0;
    }
    return 0;
}