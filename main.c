#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <math.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <unistd.h>

//Sha 265 Hash Encoding
#define uchar unsigned char
#define uint unsigned int
#define DBL_INT_ADD(a,b,c) if (a > 0xffffffff - (c)) ++b; a += c;
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))
#define MAX_TOKENS 1000 // Maximum number of hexadecimal inputs
#define MAX_PACKET_SIZE 100000 //Max number of packets that can be captured

void capturePacket() {
	const char *command = "sudo tcpdump -xqli ens33 >> tcpdump.txt"; //appends the output to the file

	int ret = system(command);
    if(ret == -1) {
	    perror("Failed to capture packets\n");
    	exit(EXIT_FAILURE);
    }
}

int getIP(char *ip) {

}

void ReadPacket() {

}

void readInRealTime(const char *file_name) {
	FILE *fp;
	char buffer[16777216]; //2^24 Adjust size as needed
	long last_position = 0;

	while (1) {
		fp = fopen(file_name, "a+");
		if (fp == NULL) {
			perror("Failed to open file");
			exit(1);
		}

		// Move the file pointer to the last read position
		fseek(fp, last_position, SEEK_SET);

		// Read new lines added to the file
		while (fgets(buffer, sizeof(buffer), fp) != NULL) {
			 //This is where we would add the functionality of analyzing the packets
		}

		// Update the last read position
		last_position = ftell(fp);

		fclose(fp);
		sleep(1); // Adjust to control polling frequency
	}
}

//Using code from https://www.programmingalgorithms.com/algorithm/sha256/c/
// This code is used to make Hash Encoding work
typedef struct {
	uchar data[64];
	uint datalen;
	uint bitlen[2];
	uint state[8];
} SHA256_CTX;

uint k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void SHA256Transform(SHA256_CTX *ctx, uchar data[])
{
	uint a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for (; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void SHA256Init(SHA256_CTX *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen[0] = 0;
	ctx->bitlen[1] = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void SHA256Update(SHA256_CTX *ctx, uchar data[], uint len)
{
	for (uint i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			SHA256Transform(ctx, ctx->data);
			DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], 512);
			ctx->datalen = 0;
		}
	}
}

void SHA256Final(SHA256_CTX *ctx, uchar hash[])
{
	uint i = ctx->datalen;

	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		SHA256Transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], ctx->datalen * 8);
	ctx->data[63] = ctx->bitlen[0];
	ctx->data[62] = ctx->bitlen[0] >> 8;
	ctx->data[61] = ctx->bitlen[0] >> 16;
	ctx->data[60] = ctx->bitlen[0] >> 24;
	ctx->data[59] = ctx->bitlen[1];
	ctx->data[58] = ctx->bitlen[1] >> 8;
	ctx->data[57] = ctx->bitlen[1] >> 16;
	ctx->data[56] = ctx->bitlen[1] >> 24;
	SHA256Transform(ctx, ctx->data);

	for (i = 0; i < 4; ++i) {
		hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

char* SHA256(char* data) {
	int strLen = strlen(data);
	SHA256_CTX ctx;
	unsigned char hash[32];
	char* hashStr = malloc(65);
	strcpy(hashStr, "");

	SHA256Init(&ctx);
	SHA256Update(&ctx, data, strLen);
	SHA256Final(&ctx, hash);

	char s[3];
	for (int i = 0; i < 32; i++) {
		sprintf(s, "%02x", hash[i]);
		strcat(hashStr, s);
	}

	return hashStr;
}


void LogTraffic(char IPaddress[])
{
    //************************************************************************
    //Written by Ethan Dastick
    //Written on Nov 3, 2024 (11/3/2024)
    //Created a function that appends the IP address to the log file. If no file exists,
    //a new file is created.
    //
    //Change Log:
    // 11/6/2024 - Ethan Dastick
    // No direct change to code. Added Log-and-ACL folder to directory and it
    // magically started working as intended :/
    // Todo: Make sure this works with an array containing multiple elements;
    // ie: [IP], [date], [Souce URL]... etc.
    //************************************************************************

    FILE* logFile = fopen("..\\Log-and-ACL\\NetworkLog.csv", "a");
    //Opening the file to append a log entry
    //SE-300-Filewall-Project-Fall-2024\\

    if(!logFile) {
        // The file did not exist, creating a new one.
        fclose(logFile);

        logFile = fopen("..\\Log-and-ACL\\NetworkLog.csv", "w");

        fprintf(logFile,"File Created\n");
        fclose(logFile);
        return;
    }

    fprintf(logFile, "%s\n", IPaddress);
    //Appending the IP to the file

    fclose(logFile);
    //Closing the file
}

void spacePackets(const char *input) {
    int length = strlen(input);
    int i = 0;

    while (i < length) {
        // If we encounter "0x", skip everything until we reach a ":"
        if (i + 1 < length && input[i] == '0' && input[i + 1] == 'x') {
            // Skip over "0x" and everything until we find a colon ":"
            while (i < length && input[i] != ':') {
                i++;
            }
            i++; // Skip over the colon as well
        } else if (isspace(input[i]) || !isxdigit(input[i])) {
            // Skip spaces and non-hexadecimal characters
            i++;
        } else {
            // Print the current valid pair of hexadecimal characters
            printf("%c%c", input[i], input[i + 1]);

            // Add a space after each pair unless it's the last pair
            if (i + 2 < length) {
                printf(" ");
            }

            // Skip the second character of the current pair
            i += 2; // Move forward to the next pair
        }
    }

    printf("\n");  // End the output with a newline
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


int main(int argc, char *argv[]) {
    // FindDeviceInfo();
    // const char *input = "c0 a8 ce 82"; // Example input 22 a0 90 bf
    // HexToDec(input); // Call the function to process the input
    // HexToASCII(input);

	// printf("Hashed: %s\n", SHA256(FakeIPaddress));
	// printf("Hashed: %s\n", SHA256("Hello World!"));
	// printf("Hashed: %s\n", SHA256("Test2"));

	// spacePackets("4500 0152 72c7 0000 8011 a8fd c0a8 ce02 c0a8 ce82 0035 8ad6 013e fffc 0fe2 8180 0001 0002 0003 0005 0235 3603 3139 3003 3132 3503 3138 3507 696e 2d61 6464 7204 6172 7061 0000 0c00 01c0 0c00 0c00 0100 0000 0500 230a 7072 6f64 2d6e 7470 2d33 046e 7470 3103 7073 3509 6361 6e6f 6e69 6361 6c03 636f 6d00 c00c 000c 0001 0000 0005 0023 0a70 726f 642d 6e74 702d 3304 6e74 7034 0370 7335 0963 616e 6f6e 6963 616c 0363 6f6d 00c0 0f00 0200 0100 0000 0500 1303 6e73 3109 6361 6e6f 6e69 6361 6c03 636f 6d00 c00f 0002 0001 0000 0005 0006 036e 7333 c09b c00f 0002 0001 0000 0005 0006 036e 7332 c09b c097 0001 0001 0000 0005 0004 b97d be41 c0b6 0001 0001 0000 0005 0004 5bbd 5b8b c0c8 0001 0001 0000 0005 0004 b97d be42 c097 001c 0001 0000 0005 0010 2620 002d 4000 0001 0000 0000 0000 0043 c0c8 001c 0001 0000 0005 0010 2620 002d 4000 0001 0000 0000 0000 0044");

	capturePacket();
	readInRealTime("tcpdump.txt");
	return 0;
}

