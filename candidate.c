
#define _POSIX_SOURCE
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

/** Name: Sarah Lively
 ** Email: slively1@umbc.edu
 ** Description: Takes in a string argument and counts number of votes 
 ** candidate receives using signal handlers and the candidate's PID.
 **/

int numVotes = 0;
/**
 ** Function description: Increases number of votes for a candidate
 **
 **/
static void sigusr1_handler(int signum) {

  numVotes += 1;
  
}

/**
 ** Function description: Prints number of votes for candidate
 **
 **/
static void sigusr2_handler(int signum) {

  // Write 32 bit LE to stderr
  fprintf(stderr, "Number of votes: %d\n", numVotes);

}
/**
 ** Function description: Changes number of votes to value requested
 **
 **/
static void sigalrm_handler(int signum) {

  numVotes = signum;

}
/**
 ** Function description: Sets up signal handlers for different situations 
 ** (incrementing votes, printing votes, changing votes) and checks for bad
 ** input.
 **/
int main(int argc, char **argv) {

  if (argc != 2) {

    printf("Incorrect amount of arguments %d\n", argc);
    
  }

  else {

    printf("I am candidate %s at PID %d\n", argv[1], getpid());
    sigset_t mask;
    sigemptyset(&mask);
    struct sigaction sa = {
      
      .sa_handler = sigusr1_handler,
      .sa_mask = mask,
      .sa_flags = 0
      
    };

    sigaction(SIGUSR1, &sa, NULL);
    struct sigaction s2 = {

      .sa_handler = sigusr2_handler,
      .sa_mask = mask,
      .sa_flags = 0

    };
    
    sigaction(SIGUSR2, &s2, NULL);

    struct sigaction s3 = {

      .sa_handler = sigalrm_handler,
      .sa_mask = mask,
      .sa_flags = 0
    };

    sigaction(SIGALRM, &s3, NULL);
    
    errno = 0;
    
    while(fgetc(stdin) != EOF || errno == EINTR) {

      errno = 0;
    }

    //    perror("Error \n");
    printf("PID %d terminating\n", getpid());
    
  }
  
  return 0;

}
