/**
   Name: Sarah Lively
   Email: slively1@umbc.edu
   Description: 
   Resources: Andrew Henry (ahenry3@umbc.edu), http://www.tutorialspoint.com/c_standard_library/c_function_fgets.htm, https://stackoverflow.com/questions/4964142/how-to-spawn-n-threads, https://stackoverflow.com/questions/174531/how-to-read-the-content-of-a-file-to-a-string-in-c
   Part 6 Documentation: Restaurants are producers and driver threads are consumers. Orders are the data items being produced.
Race condition can occur if the state is updated in between the printing of the driver status by the main thread and the changing of the status by the driver thread.  
 **/

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

const int NUM_SECONDS = 0.25;

 typedef struct 
  {
    int x;
    int y;
  } restaurants;

  typedef struct 
  {
    int x;
    int y;
  } customers;

  typedef struct 
  {
    int rNum;
    int cNum;
  } orders;

  typedef struct 
  {
    restaurants r;
    customers c;
  } threadStruct;

threadStruct *tPtr;

/**
 ** Function description: This function allows the given thread to sleep for
 ** the Manhattan distance twice, once for the driver to get to the 
 ** restaurant and once for the driver to get to the customer's home.
 **/
void travel() {

  //Need to know which thread to be using- pass above threads variable??
  
  sleep(abs(tPtr->r.x - tPtr->c.x) + abs(tPtr->r.y - tPtr->c.y) * NUM_SECONDS);
  sleep(abs(tPtr->r.x - tPtr->c.x) + abs(tPtr->r.y - tPtr->c.y) * NUM_SECONDS);

}

/**
 ** Function description: Sets up threads
 **/
void *func() {

  travel();
  return NULL;
  
}

/**
 ** Function description: Spawns D threads as read in by the file. Prints when driver reaches
 ** destination of customer's home, then increments order counter.
 **/
void dthreads(int d) {

  pthread_t *threads = malloc(sizeof(pthread_t)*d);
  int counts[d];
  threadStruct t;
  tPtr = &t;
  for (int i = 0; i < d; i++) {

    //initialize counters to zero
    counts[i] = 0;
    //pass ptr to struct of restaurant and customer structs
    pthread_create(&threads[i], NULL, func, tPtr);
    //travel();
    printf("Driver has arrived!\n");
    counts[i] += 1; 
    pthread_join(threads[i], NULL);
    
  }

}


/**
 ** Function description: This function goes through the file line by line
 ** and stores the number of drivers, coordinates of restaurant locations,
 ** coordinates of customer locations, and order descriptions. Except for the
 ** number of drivers, all other data is stored in a given struct.
 **/

int main(int argc, char **argv) {

  FILE *fp;
  char *lines = 0;
  long length = 0;
  int i = 0;
  int count = 0;
  int d;

  if (argc != 3) {

    printf("Incorrect number of arguments\n");
    return 0;
    
  }
    
  fp = fopen(argv[1], "r");

  if (fp) {

    int val = 0;
    fseek(fp, 0, SEEK_END);
    length = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    lines = malloc(length);
    if (lines) {
      
      val = fread(lines, 1, length, fp);

      if (val == 0)
	printf("Error reading file\n");
    }
    fclose(fp);
  }

  restaurants r[20];
  customers c[20];
  orders o[length - 1];
  
  while (i < length) {

    if (count == 0) {
      
      d = atoi(&lines[i]);
      printf("%d\n", d);
      
    }

    else if (count >= 1 || count <= 20) {

      int pos = (count - 1) / 2;

      if (count % 2 == 0) {
	
	r[pos].y = atoi(&lines[i]);
	printf("%d", r[pos].y);
	
      }
      else {
	
	r[pos].x = atoi(&lines[i]);
	printf("%d", r[pos].y);

      }
      
    }
    
    else if (count <= 21 || count <= 40) {

      int pos = (count - 1) / 2;
      
      if (count % 2 == 0) {

	c[pos].y = atoi(&lines[i]);
	printf("%d\n", c[pos].y);

      }
      
      else {

	c[pos].x = atoi(&lines[i]);
	printf("%d\n", c[pos].x);

      }

      dthreads(d);
      
    }

    else {

      int pos = (count - 1) / 2;
      
      if (count % 2 == 0) {

	o[pos].cNum = atoi(&lines[i]);
	printf("%d\n", o[pos].cNum);
	
      }
      
      else {

	o[pos].rNum = atoi(&lines[i]);
	printf("%d\n", o[pos].rNum);
		
      }
    }
    
    i += 1;
    
  }

  return 0;
  
}
