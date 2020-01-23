#include <stdio.h>
#include <string.h>
#include <unistd.h> // for getting the pid
#include <stdlib.h>

#include "thread.h"
#include "shell.h"
#include "shell_commands.h"

#include "aodvv2/aodvv2.h"
#include "writer.h"


int main(void)
{
    aodv_init();

    (void) puts("Welcome to RIOT!");
    
  /*   char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE); */

    return 0;
}
