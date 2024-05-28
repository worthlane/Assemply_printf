#include <stdio.h>

extern "C" int _print(const char* format, ...);

int main()
{
    _print("%d", 5);
}
