#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
//#include <pcap.h>

#define MAX_TOKENS 1000 // Maximum number of hexadecimal inputs

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
    bool invalid = false;

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
                invalid = true;
                break; // Stop processing this token on error
            }

            // Update decimal value
            decimal += value * base;
            base *= 16; // Move to the next power of 16
        }
            // Print the decimal value
           if(decimal != 0) {
               printf("Hex: %s -> Decimal: %d\n", token, decimal);
           }

            //Calc the total
            total += decimal;

            token = strtok(NULL, " "); // Get the next token


        }
    if (total != 0){
        // Print the total sum of all decimal values
        printf("Total Decimal Value: %d\n", total);
        }
}

int createBlackList() {
    const char *fileName = "BlackList.txt";
    //Creates a pointer to the file, then opens the file with "fileName" and opens it to write mode
    FILE *file = fopen(fileName, "w");
    if (file == NULL) {
        printf("File does not exist\n");
        return EXIT_FAILURE; //Terminates the program and informs the operating system that it was unsuccessful
    }
    fprintf(file,"This is your Black List File. Please save this file in an easily accessible location for your convince. \n In the lines below you will write the Domain name of the websites that you wish to block. An example would be 'Google.com' \n Please make sure to write each website on its OWN LINE. \n ");
    fclose(file);
}

int createWhiteList() {
    const char *fileName = "WhiteList.txt";
    //Creates a pointer to the file, then opens the file with "fileName" and opens it to write mode
    FILE *file = fopen(fileName, "w");
    if (file == NULL) {
        printf("File does not exist\n");
        return EXIT_FAILURE; //Terminates the program and informs the operating system that it was unsuccessful
    }
    fprintf(file,"This is your White List File. Please save this file in an easily accessible location for your convince. \n In the lines below you will write the Domain name of the websites that you wish to grant clearance from the firewall. An example would be 'Google.com' \n Please make sure to write each website on its OWN LINE. \n ");
    fclose(file);
}

    // int findDeviceInfo() {
    //     char  ip[13], subnet_mask[14];

    //     bpf_u_int32 ip_raw; // IP address as an int
    //     bpf_u_int32 subnet_mask_raw; // Subnet Mask as an int

    //     char error_buffer[PCAP_ERRBUF_SIZE]; // Size defined in pcap.h
    //     struct in_addr address;

    //     //Finds a Device
    //     char *device = pcap_lookupdev(error_buffer); // Name of device
    //     if (device == NULL) {
    //         printf(" %s\n", error_buffer);
    //         return 1;
    //     }

    //     /*Get Device Info*/
    //     int lookup_return_code = pcap_lookupnet(device, &ip_raw, &subnet_mask_raw, error_buffer);
    //     if (lookup_return_code == -1) {
    //         printf("%s\n", error_buffer);
    //         return 1;
    //     }

    //     // Readable IP
    //     address.s_addr = ip_raw;
    //     strcpy(ip, inet_ntoa(address));
    //     if (inet_ntoa(address) == NULL) {
    //         perror("inet_ntoa"); /* print error */
    //         return 1;
    //     }

    //     //Readable subnet mask
    //     address.s_addr = subnet_mask_raw;
    //     snprintf(subnet_mask, sizeof(subnet_mask), inet_ntoa(address));
    //     if (inet_ntoa(address) == NULL) {
    //         perror("inet_ntoa");
    //         return 1;
    //     }

    //     printf("Device: %s\n", device);
    //     printf("IP address: %s\n", ip);
    //     printf("Subnet mask: %s\n", subnet_mask);

    //     return 0;
    // }



    int main(int argc, char *argv[]) {
        // FindDeviceInfo();
        // const char *input = "42 6F 6F 62 73"; // Example input
        const char *input = "FG";
        //HexToDec(input); // Call the function to process the input
        //HexToASCII(input);
        createBlackList();
        return 0;
    }

