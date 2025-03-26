#include <stdio.h>
#include <string.h>

#include "c_secrecy.h"

void log_in_user(Secret_t *username, Secret_t *password, char *host)
{
    // this will be garbled rubbish
    printf("logging in user: %.*s with password %.*s to %s\n", 
        username->value_len, 
        username->value, 
        password->value_len, 
        password->value, 
        host
    );

    // this will be valid stuff
    printf("logging in user: \"%.*s\" with password \"%.*s\" to machine \"%s\"\n", 
        username->value_len, 
        expose_secret_inline(username), 
        password->value_len, 
        expose_secret_inline(password), 
        host
    );
}

void main(int argc, char **argv)
{
    Secret_t *user_name;
    Secret_t *user_password;

    // error handling for input parameters
    if (argc != 3)
    {
        printf("Need to include [username] and [password] in command invocation.\n");
        return;
    }

    if (strlen(argv[1]) > 20)
    {
        printf("Username supplied is too long\n");
        return;
    }

    if (strlen(argv[2]) > 20)
    {
        printf("Password supplied is too long\n");
        return;
    }

    user_name = create_secret(argv[1], strlen(argv[1]));
    user_password = create_secret(argv[2], strlen(argv[2]));

    log_in_user(user_name, user_password, "localhost");

    delete_secret(user_name);
    delete_secret(user_password);

    return;
}