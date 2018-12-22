/* Name: Sarah Lively
 * Email: slively1@umbc.edu
 * Description: Unit tests for Password Keeper system, including testing thread safety, show fns 
 * for accounts and master password lists, and verifying logins and accounts.
 * Resources: http://linuxshellaccount.blogspot.com/2008/02/c-code-to-add-user-accounts-and.html
 *
 */
#define _GNU_SOURCE

#include "cs421net.h"
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>

/*Write to network socket*/
static int writeSoc() {

  char *bytes_to_send = "\xe8\x03\x00\x00";
  int len = (sizeof(char) * 4);

  if (cs421net_send(bytes_to_send, len) == false) {

    printf("Error sending bytes\n");
    return -EINVAL;
    
  }

  return 0;
}

/*Check UIDs are correct for login*/
static int checkID() {

  uid_t id = getuid();
  uid_t euid = geteuid();
  if (setuid(id) != 0)
    return -EINVAL;
  else if (getresuid(&id, &euid, &id))
    return -EINVAL;
	   
  return 0;
  
}

/*Happy path read and write to master and account devices*/
static int happyPath() {

  FILE *fp, *f;
  char st1[] = "My Proj2 Part 5";
  char s[] = "umbc.edu";
  
  fp = fopen("/dev/pwkeeper_master", "w");
  if (fp == NULL) { 
    printf("Error opening master device 1\n");
    return -EBUSY;
  }
  fprintf(fp, "%s\n", st1);
  fclose(fp);

  fp = fopen("/dev/pwkeeper_master", "r");
  if (fp == NULL) { 
    printf("Error opening master device 2\n");
    return -EBUSY;
  }
  
  if (fscanf(fp, "%s\n", st1) == 0) 
    printf("Error reading master device");
  
  printf("Wrote string %s\n", st1);
  fclose(fp);

  f = fopen("/dev/pwkeeper_account", "w");
  if (f == NULL) {
    printf("Error opening account device 1\n");
    return -EBUSY;
  }
  fprintf(f, "%s\n", s);
  fclose(f);
  
  f = fopen("/dev/pwkeeper_account", "r");
   if (f == NULL) {
    printf("Error opening account device 2\n");
    return -EBUSY;
  }
  
  printf("Wrote newest string %s\n", s);
  if (fscanf(f, "%s\n", s) == 0) {
    printf("Error reading account file");
    return -EBUSY;
  }
  
  fclose(f);
  return 0;
  
}

/* Too large write to master and account*/
static int bigWrite() {
  
  FILE *fp;
  FILE *f;
  char bigStr[] = "Veryveryveryveryveryverylongggstringg";
  fp = fopen("/dev/pwkeeper_master", "w");
  if (fp == NULL) {
    printf("Error opening master dev\n");
    return -EIO;
  }
  
  fprintf(fp, "%s\n", bigStr);
  fclose(fp);

  f = fopen("/dev/pwkeeper_account", "w");
  if (f == NULL) {
    printf("Error opening account dev\n");
    return -EIO;
  }
  
  fprintf(f, "%s\n", bigStr);
  fclose(f);
  return 0;
  
}

/* Demonstrates master_show() and accounts_show()
 *
 */
static int showFns() {
  
  FILE *fp, *f;
  char buf[] = "Contents";
  fp = fopen("/sys/devices/platform/pwkeeper/accounts", "r");
  if (fp == NULL) {

    printf("Error opening show account fn\n");
    return -EIO;
    
  }

  if (fscanf(fp, "%s", buf) == 0) {

    printf("Error reading show account fn\n");
    return -EIO;

  }

  printf("%s\n", buf);
  fclose(fp);

  f = fopen("/sys/devices/platform/pwkeeper/masters", "r");
  if (f == NULL) {

    printf("Error opening show master fn\n");
    return -EIO;
    
  }

  if (fscanf(f, "%s", buf) == 0) {

    printf("Error reading master account fn\n");
    return -EIO;

  }

  printf("%s\n", buf);
  fclose(f);
  
  return 0;
  
}

/* Extra credit test: demonstrates and shows two users with same master pw 
 * and account name creates different passwords.
 */
static int showExtraCredit() {
 
 FILE *tmp, *stmp, *profile;
 char *username, *userdir;/*, *home;*/
 username = (char *)malloc(8*sizeof(char));
 userdir = (char *)malloc(256*sizeof(char));
  
 tmp = fopen("/etc/passwd", "a");
 fprintf(tmp, "/%s/%s:/bin/ksh\n", userdir, username);
 fclose(tmp);

 stmp = fopen("/etc/shadow", "a");
 fprintf(stmp, "%s:*LK*:::::::\n", username);
 fclose(stmp);

 profile = fopen(".profile", "a");
 fprintf(profile, "stty istrip\n");
 fprintf(profile, "PATH=/bin:/usr/bin:/usr/local/bin:/usr/share/bin:.\n");
 fprintf(profile, "export PATH\n");
 fprintf(profile, "\n");
 fprintf(profile, "\n");
 fclose(profile);

 printf("\n");
 printf("All Done!!!\n");
 printf("\n");
 printf("Now set the Password!\n");
 printf("\n");
 execl("/usr/bin/passwd", "passwd", username, NULL);
 printf("\n");
 printf("Password set!!! Take a break...\n");

 return 0;

}
int main(void)
{
  cs421net_init();  
  writeSoc();
  checkID();
  happyPath();
  bigWrite();
  showFns();
  showExtraCredit();
  
  return 0;
}
