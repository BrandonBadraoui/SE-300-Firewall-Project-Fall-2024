#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
//#include <pcap.h>

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

void FreeWillie() { //Will free the register from the packets data after we determine we do not want it

}

void SendPort() {

}

void ReceivePort() {

}

void IP_to_Domain() {//converts ip address to a domain name

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
                fprintf(stderr, "Invalid hexadecimal character: %c\n", token[i]);
                break; // Skip to the next token
            }

            // Update decimal value
            decimal += value * base;
            base *= 16; // Move to the next power of 16
        }

        // Print the result for the current hex number
        printf("Hexadecimal: %s Decimal: %d\n", token, decimal);

        // Add to the total
        total += decimal;

        token = strtok(NULL, " "); // Get the next token
    }
    // Print the total sum of all decimal values
    printf("Total Decimal Value: %d\n", total);
}

// int findDevice() {
//
// }


int main(int argc, char *argv[]){
    char *dev = argv[1];

    printf("Device: %s\n\n", dev);


    const char *input = "B00B 5000";

    HexToDec(input); // Call the function with the hardcoded value



    return 0;
}


