
#define _POSIX_SOURCE
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

/** 
 ** Name: Sarah Lively
 ** Email: slively1@umbc.edu
 ** Description: Takes in 4 candidates and prints out main menu. Depending on 
 ** user input, the program allows the user to vote, shows vote counts, or 
 ** allows the user to commit voter fraud.
 ** Part 5: As long as the writing end of a given pipe is open, it can be assumed that 
 ** writing can occur. The system won't report back with an EOF, since a writing end
 ** is still open. If the pipe is open for reading and writing by different 
 ** processes without being closed, then it is possible to overwrite data/read an old copy of 
 ** data (race condition).
 **/

const int NUM_FDS = 16;
const int OPT_ZERO = 0;
const int OPT_ONE = 1;
const int OPT_TWO = 2;
const int OPT_THREE = 3;

/**
 ** Function description: This program creates 16 file descriptors and 4 child processes. It also
 ** calls the candidate program and passes the ballot arguments. It also takes in user input 
 ** based on a menu, allowing the user to close the child processes' writing ends of the pipes,
 ** sends a SIGUSR1 signal for the selected candidate, shows the SIGUSR2 signal results for
 ** each candidate, and allows the user to enter a new vote count.
 **/
int main(int argc, char**argv) {

  int numArgs = 5;
  int fd[NUM_FDS];
  int p1;
  int p2;
  pid_t p;
  char *ptr = NULL;
  pid_t pids[numArgs - 1];
  
  if (argc != numArgs) {

    printf("Incorrect number of arguments\n");

  }

  else {

    for (int i = 0; i < numArgs - 1; i++) {

      p1 = pipe(fd + 4 * i);
      p2 = pipe(fd + 2 + 4 * i);

      if (p1 == -1) {

	printf("Error with pipe p1\n");
	return -1;
	
      }

      else if (p2 == -1) {

	printf("Error with pipe p2\n");
	return -1;

      }
      
    }
    
    for (int j = 0; j < numArgs - 1; j++) {

      p = fork();
      pids[j] = p;
      
      if (p == 0) {

	dup2(fd[4 * j], 0);
	close(fd[4 * j]);
	dup2(fd[3 + 4 * j], 2);
	close(fd[3 + 4 * j]);	
	for (int k = 0; k < numArgs - 1; k++) {

	  close(fd[1 + 4 * k]);
	  close(fd[2 + 4 * k]);
	  
	}

	 int error = 0;
	 error = execlp("./candidate", "candidate", argv[j+1], ptr);

	 if (error == -1)
	   perror("Error ");
	 
	break;

      }
      
      
    }

    if (p != 0) {

      for (int k = 0; k < numArgs - 1; k++) {

	close(fd[4 * k]);
	close(fd[3 + 4 * k]);

      }
      
      int input = 0;
      int status = 0;
      while (1) {

	printf("Main Menu: \n 0. End program \n 1. Cast ballot \n 2. Show vote counts\n 3. Set vote count\n");
	if (scanf("%d", &input) == EOF)
	  printf("Error reading input\n");

	else {

	  if (input == OPT_ZERO) {

	    for (int k = 0; k < numArgs - 1; k++) {

	      close(fd[1 + 4 * k]);
	      waitpid(pids[k], &status, 0);
	       
	    }

	    return 0;
	  }

	  else if (input == OPT_ONE) {

	    int vote = 0;
	    for (int i = 0; i < numArgs - 1; i++) {

	      printf("%d. %s\n", i, argv[i + 1]);
	      
	    }
	    
	    if (scanf("%d", &vote) == EOF)
	      printf("Error reading vote");

	    else {
	      
	      int value = 0;
	      value = kill(pids[vote], SIGUSR1);
	      if (value == 0)
		printf("Voted\n");
	    }
	  }
	  else if (input == OPT_TWO) {

	    int returnVal = 0;
	    int votes[100];
	    for (int i = 0; i < numArgs - 1; i++) {

	      int value = 0;
	      value = kill(pids[i], SIGUSR2);

	      if (value != 0)
		printf("Error in sending signal\n");

	      else {
		
		returnVal = read(pids[3 + 4 * i], votes, 100);
		if (returnVal != 0)
		  printf("Error reading pids\n");

		else {
		  printf("Total votes: %d\n", votes[i]);
		  close(pids[3 + 4 * i]);

		}
	      }
	    }
	  }

	  else if (input == OPT_THREE) {

	    int choice = 0;
	    char numVotes[NUM_FDS];
	    for (int i = 0; i < numArgs - 1; i++) {

	      printf("%d. %s\n", i, argv[i + 1]);
	      
	    }
	    
	    if (scanf("%d", &choice) == EOF)
	      printf("Error reading vote");

	    else {

	      printf("Enter new vote count\n");

	      if (fgets(numVotes, NUM_FDS, stdin) == NULL)
		printf("Error reading vote count");

	      else {

		int ret = 0;
		ret = kill(pids[choice], SIGALRM);

		if (ret != 0)
		  printf("Error sending alarm signal\n");

		else {

		  for (int i = 0; i < numArgs; i++) {
		    int writeRet = 0;
		    writeRet = write(pids[4 * i], numVotes, sizeof(numVotes));
		    
		    if (writeRet != 0)
		      printf("Error writing new votes\n");
		  }
		}
	      }
	    }

	  }
	  
	  else
	    printf("Bad input\n");
	  
	}
      }
    }
  }
  return 0;
  
}
