#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    // Declare local variables
    int local_1c;
    int local_18;
    unsigned int local_14;
    unsigned int local_10;
    unsigned int local_c;

    // Accept user input and assign it to the local variables
    scanf("%d", &local_1c);
    scanf("%d", &local_18);
    scanf("%u", &local_14);
    scanf("%u", &local_10);
    scanf("%u", &local_c);

    // Check whether the conditions for each variable are met
    // If a condition is not met, output "Wrong password." and terminate the program
    if (local_1c != -0x5c27d512) {
        puts("Wrong password.");
        exit(1);
    }

    if (local_18 != -0x38428c6e) {
        puts("Wrong password.");
        exit(1);
    }

    if (local_14 % 0x557bc != 0x1092e) {
        puts("Wrong password.");
        exit(1);
    }

    if (local_10 % 0x4ba5c6b != 0x1dd588b) {
        puts("Wrong password.");
        exit(1);
    }

    if (local_c % 0x2ba501a != 0x25c5a4c) {
        puts("Wrong password.");
        exit(1);
    }

    // If all conditions are met, output "Deactivated."
    puts("Deactivated.");

    return 0;
}

