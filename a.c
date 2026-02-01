#include <stdio.h>

void func() {
    printf("func\n");
}

int main() {
    int i = 0;
    printf("Hello, World!\n");
    ++i;
    printf("i = %d\n", i);
    func();
    return 0;
}
