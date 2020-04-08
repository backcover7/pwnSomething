#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]){
    long timestamp = atol(argv[1]);
    int captcha = atoi(argv[2]);
    int rands[8];
    int canary;
    srand(timestamp);

    for (int i = 0; i <= 7; i++) 
        rands[i] = rand();
    
    // captcha = v6 - v8 + v9 + v10 + v4 - v5 + v3 + v7;
    // v10 = captcha - v3 - v4 + v5 - v6 - v7 + v8 - v9;
    // v10 = captcha - r1 - r2 + r3 - r4 - r5 + r6 - r7
    canary = captcha - rands[1] - rands[2] + rands[3] - rands[4] - rands[5] + rands[6] - rands[7];
    printf("%d\n", canary);
    return 0;
}