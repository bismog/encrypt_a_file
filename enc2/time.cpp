
#include <stdio.h>
#include <time.h>

int main() {
    int cur = time(NULL);
    printf("current time: %lu.\n", cur);

    return 0;
}
