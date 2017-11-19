// not the original challenge code
// reconstructed by reverse engineering
#include <stdio.h>
#include <stdlib.h>

int main() {
  int result;

  size_t heap_size;
  char* heap_block;

  // allocate a block of user-specified size on the heap
  if ( scanf("%zx", &heap_size) == 1 && (heap_block = calloc(heap_size, 1uLL)) != 0LL ) {
    while ( 1 ) {
      // overwrite heap_block + user-specified offset with user-specified byte
      char byte = 0;
      size_t idx;
      if ( scanf("%zx %hhx", &idx, &byte) != 2 )
        break;
      *(heap_block + idx) = byte;
    }
    result = 0;
  } else {
    puts(":(");
    result = -1;
  }

  return result;
}
