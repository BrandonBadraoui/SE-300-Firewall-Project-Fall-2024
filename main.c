#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

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

int HexToDec(const char *hex) {
    int decimal = 0;
    int base = 1; //base 16

    //Get the length of the hex string
    int length = strlen(hex);

    //loop through each digit in the hex string
    for (int i = length - 1; i >= 0; i--) {
        char currChar = hex[i];


        // Convert character to uppercase to simplify comparison
        if (currChar >= 'a' && currChar <= 'f') {
            currChar = toupper(currChar);
        }

        //Determine the decimal value of the current character
        int value;
        if (currChar >= '0' && currChar <= '9') {
            value = currChar - '0';
        } else if (currChar >= 'A' && currChar <= 'F') {
            value = currChar - 'A' + 10;
        }else {
            //invlaid hex digit
            fprintf(stderr, "Invalid Hexadecimal Character %c\n", hex[i]);
            return -1;
        }
        // Update decimal value
        decimal += value * base;
        base *= 16; // Move to the next power of 16
    }
    return decimal;
}


int main(void) {
    const char *hexNumber = "B00B5"; // Example hex number
    int decimalValue = HexToDec(hexNumber);

    if (decimalValue != -1) {
        printf("Hexadecimal: %s\nDecimal: %d\n", hexNumber, decimalValue);
    }

    return 0;
}


