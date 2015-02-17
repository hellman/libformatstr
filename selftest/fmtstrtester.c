#include <stdio.h>
#include <sys/mman.h>

int main(int argc, char **argv) {
    char *target = NULL;
    char fill = '\x00';
    int n = 0;

    srand(time(NULL));
    fill = rand() & 0xff;

    target = mmap (0x33333000, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, (off_t)0);
    memset(target, fill, 4096);
    printf(argv[1]);
    // first output the fill character, then dump the mmap'ed region
    fwrite(&fill, 1, 1, stderr);
    fwrite(target, 1, 4096, stderr);

    return 0;
}
