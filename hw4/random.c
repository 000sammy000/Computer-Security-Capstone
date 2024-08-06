#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

char secret[0x10];

void init(unsigned int seed)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    srand(seed); // Use the provided seed
    for (int i = 0; i < 0x10; i++)
    {
        secret[i] = 48 + (rand() % (126 - 47) + 1);
    }
    
}

int main(int argc, char *argv[]){
    if(argc != 2) {
        printf("Usage: %s [seed]\n", argv[0]);
        return 1;
    }

    unsigned int seed = atoi(argv[1]);
    init(seed);

    

    for (int i = 0; i < 0x10; i++)
    {
        printf("%c", secret[i]);
    }
    printf("\n");

    
    return 0;
}
