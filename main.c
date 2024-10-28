#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
//#include <pcap.h>

#define MAX_TOKENS 1000 // Maximum number of hexadecimal inputs

// int train() {
//     printf("Choo Choo\n\n");
//     return 1;
// }

// void sussy() {
//     printf("sussy amogus");
//     int var1 = train();
// }

void ReadPacket() { //will need to incorperate Tcdump as Tcpdump provides hexadecimal outputs

}

void DataHandler() {

}

void Firewall() {

}

void Website_Blacklist() {

}

void Hash() {

}

void FreeWillie() {
    //Will free the register from the packets data after we determine we do not want it
}

void SendPort() {

}

void ReceivePort() {

}

void IP_to_Domain() {
    //converts ip address to a domain name
}


void HexToASCII(const char *input) {
    char inputCopy[1000];
    strcpy(inputCopy, input);

    // Tokenize the input string using space as a delimiter
    char *token = strtok(inputCopy, " ");
    while (token != NULL) {
        int decimal = 0; // Initialize decimal value
        int base = 1; // Base for hex conversion

        // Get the length of the hex string
        int len = strlen(token);

        // Convert hex to decimal
        for (int i = len - 1; i >= 0; i--) {
            char currentChar = token[i];

            // Convert character to uppercase
            if (currentChar >= 'a' && currentChar <= 'f') {
                currentChar = toupper(currentChar);
            }

            int value;
            if (currentChar >= '0' && currentChar <= '9') {
                value = currentChar - '0';
            } else if (currentChar >= 'A' && currentChar <= 'F') {
                value = currentChar - 'A' + 10;
            } else {
                fprintf(stderr, "Invalid hexadecimal character: %c\n", currentChar);
                token = strtok(NULL, " "); // Skip to the next token
                continue;
            }

            // Update decimal value
            decimal += value * base;
            base *= 16; // Move to the next power of 16
        }

        // Convert decimal to ASCII and print
        if (decimal >= 0 && decimal <= 127) {
            printf("%c ", (char)decimal);
        } else {
            printf("Hex: %s -> Invalid ASCII value\n", token);
        }

        token = strtok(NULL, " "); // Get the next token
    }
}

void HexToDec(const char *input) {
    char hex[100]; // Buffer for each hexadecimal number
    int decimal;
    int total = 0; // Variable to accumulate the total decimal value

    // Create a mutable copy of the input
    char inputCopy[1000];
    strcpy(inputCopy, input);

    // Tokenize the input string using space as a delimiter
    char *token = strtok(inputCopy, " ");
    while (token != NULL) {
        decimal = 0; // Reset decimal for each hex number
        int base = 1; // Base 16

        // Get the length of the hex string
        int len = strlen(token);

        // Loop through each character in the hex string
        for (int i = len - 1; i >= 0; i--) {
            char currentChar = token[i];

            // Convert character to uppercase to simplify comparison
            if (currentChar >= 'a' && currentChar <= 'f') {
                currentChar = toupper(currentChar);
            }

            // Determine the decimal value of the current character
            int value;
            if (currentChar >= '0' && currentChar <= '9') {
                value = currentChar - '0';
            } else if (currentChar >= 'A' && currentChar <= 'F') {
                value = currentChar - 'A' + 10;
            } else {
                // Invalid hex character
                fprintf(stderr, "Invalid hexadecimal character: %c\n", currentChar);
                break; // Stop processing this token on error
            }

            // Update decimal value
            decimal += value * base;
            base *= 16; // Move to the next power of 16
        }

        // Print the decimal value
        printf("Hex: %s -> Decimal: %d\n", token, decimal);

        token = strtok(NULL, " "); // Get the next token
    }
    // Print the total sum of all decimal values
    printf("Total Decimal Value: %d\n", total);
}

// int findDevice() {
//     int argc;
//     char **argv;
//     // Name of device
//     char error_buffer[PCAP_ERRBUF_SIZE]; // Size defined in pcap.h
//
//     //Finds a device
//     char *device = pcap_lookupdev(error_buffer);
//     if (device == NULL) {
//         printf("Error finding device: %s\n", error_buffer);
//         return 1;
//     }
//     printf("Network device found: %s\n", device);
//     return 0;
// }

int main(int argc, char *argv[]) {
    const char *input = "41 65"; // Example input
    HexToDec(input); // Call the function to process the input
    HexToASCII(input);
    return 0;
}