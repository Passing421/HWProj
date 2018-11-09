/** 
 ** Name: Sarah Lively
 ** Email: slively1@umbc.edu
 ** Description: Implementation of memory allocator
 ** Resources: Andrew Henry (ahenry3@umbc.edu), https://www.geeksforgeeks.org/program-next-fit-algorithm-memory-management/, https://www.geeksforgeeks.org/mutex-lock-for-linux-thread-synchronization/
 ** Part 2 Comments: The number of frames needed for the bytes is calculated in my_malloc(), 
 ** then stored in a global for my_free() to know which frames to deallocate.
 ** Freeing a pointer in the middle of memory will create a dangling pointer, which will point
 ** to random, uninitialized data, which is undefined behavior and should return a segfault
 ** as a signal to the user that they are using bad pointers.
 **/

#define _POSIX_SOURCE
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define SIZE 640
#define FLAGS 10
#define FREE 0
#define RESERVED 1

uint8_t mem[SIZE];
int frames[FLAGS];
int canaries[FLAGS];
int allocated;
int nextFrame;
pthread_mutex_t lock;

/**
 ** Unit test of memory allocator implementation. This will allocate and free memory region.
 **
 **/
extern void hw4_test(void); 
/**
 ** Write to stdout information about the current memory allocations.
 ** Display memory contents, one frame per line, 10 lines total. Display the actual bytes
 ** stored in memory. If the byte is unprintable (ASCII value less than 32 or greater than 
 ** 126), then display a dot instead. Also display current memory allocations. For each frame,
 ** display a 'f' if the frame is free, 'R' if reserved. If the frame is the beginning of a
 ** reserved memory block, display the four hexadecimal digit canary. Otherwise, display 
 ** dashes instead of the canary.
 **/

void my_malloc_stats(void) {

  printf("Memory contents:\n");
  for (unsigned int i = 0; i < FLAGS; i++) {

    int index = i * SIZE / FLAGS;

    for (unsigned int j = 0; j < SIZE / FLAGS; j++) {

      if (mem[index + j] < 32 || mem[index + j] > 126) {

	printf(".");
	
      }

      else {
	
	printf("%c", mem[index + j]);

      }

    }

    printf("\n");
    
  }

  printf("Memory allocation table:\n");
  
  for (unsigned int i = 0; i < FLAGS; i++) {

    if (frames[i] == FREE) {
      
      printf("f:---- ");

    }
    
    else if (frames[i] == RESERVED) {

      printf("R:%04X ", canaries[i]);

    }
    
  }

  printf("\n");
  
}

/** 
 ** Finds a block of free frames for the frame length needed for size number of bytes.
 ** If it is successful, it returns the starting index of the block or returns -1 if unable to
 ** find a block big enough for the number of bytes.
 **
 **/
int nextFit(int nextFrame, size_t size) {

  //accounts for canary and offset
  int numFrames = (((size + 2) - 1) / 64) + 1;
  allocated = numFrames;
  int j = 0;
  int gap = 0;
  nextFrame = 0;
  for (int i = nextFrame; i < FLAGS - numFrames + 1; i++) {

    gap = 1;
    nextFrame = i;
    for (j = i; j < i + numFrames; j++) {
      
      if (frames[j] == RESERVED) {

	  gap = 0;
	  nextFrame = 0;
	  break;

	}
	
      }
  }

  if (gap == 0)
    return nextFrame;
  return nextFrame;
}

/**
 ** Allocate and return a contiguous memory block that is within the memory region.
 ** The size of the returned block will be at least @a size bytes, rounded up to the next
 ** 64-byte increment. 
 ** @param size Number of bytes to allocate. If @c 0, your code may do whatever it wants;
 ** my_malloc() of @c 0 is "implementation defined", meaning it is up to you if you want to
 ** return @c NULL, segfault, whatever.
 ** @return Pointer to allocated memory, or @c NULL if no space could be found. If out of
 ** memory, set errno to @c ENOMEM.
 **/
void *my_malloc(size_t size) {

  pthread_mutex_lock(&lock);
  int index = 0;
  int x = nextFit(nextFrame, size);
  //no frames available to allocate
  if (x == -1) {
    errno = ENOMEM;
    return NULL;
  }
  for (; x < FLAGS; x++) {
    if (size + 2 >= index * 64 + 1) {
      
      frames[x] = RESERVED;
      canaries[x] = rand() & 0xff;
      nextFrame = x + 1;
    }
    
    index += 1;
  }

  pthread_mutex_unlock(&lock);
  return mem;

}
/**
 ** Assists with signal fault if segfault occurs
 **
 **/
static void my_fault_handler(int signum) {

  printf("Received signal %d\n", signum);

}

/**
 ** Deallocate a memory region that was returned by my_malloc().
 ** If @a ptr is not a pointer returned by my_malloc(), then send a SIGSEV signal to the 
 ** calling process. Likewise, calling my_free() on a previously freed region results in a 
 ** SIGSEV.
 **
 ** @param ptr Pointer to memory region to free. If @c NULL, do nothing.
 **/
void my_free(void *ptr) {

  pthread_mutex_lock(&lock);
  sigset_t mask;
  sigemptyset(&mask);
  struct sigaction sa = {
    .sa_handler = my_fault_handler,
    .sa_mask = mask,
    .sa_flags = 0
  };
  sigaction(SIGSEGV, &sa, NULL);
  sigaction(SIGUSR1, &sa, NULL);
  
  int count = 0;
  for (int i = 0; i < FLAGS; i++) {

    if (frames[i] == RESERVED) {
      frames[i] = FREE;
      count += 1;
    }

    if (ptr == NULL && canaries[i] != mem[i]) {
      
      raise(SIGUSR1);
      
    }
  }
  
  if (count == 0)
    raise(SIGSEGV);
  
  pthread_mutex_unlock(&lock);
  
}

int main(int argc, char **argv) {

  if (pthread_mutex_init(&lock, NULL) != 0) {

    printf("Mutex init failed\n");
    return -1;

  }
  unsigned int seed;
  if (argc == 1)
    seed = 0;
  else
    seed = atoi(argv[1]);

  srand(seed);
  memset(mem, 0, sizeof(mem));
  for (int i = 0; i < FLAGS; i++) {

    frames[i] = FREE;
    
  }

  hw4_test();
  /*  my_malloc(1);
  my_malloc_stats();
  my_malloc(65);
  my_malloc_stats();
  my_free(mem);
  my_malloc_stats();*/
  
  return 0;
  
}
