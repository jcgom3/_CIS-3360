/*============================================================================
| Assignment: Calculate the checksum of an input file given:
|   -> the name of the input file,
|   -> the checksum size of either 8, 16, or 32 bits
|
|
| Language: C
|
| To Compile: gcc -o pa02 pa02.c
|
| To Execute: ./pa02 inputFilename.txt checksumSize
|     (where `checksumSize` is either 8, 16, or 32)
|
| Class: CIS3360 - Security in Computing
|
| Instructor: Michael McAlpin
|
+===========================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define MAX_BUFFER 1024  // Maximum input file size in characters
#define LINE_LENGTH 80   // Number of characters per printed line
#define PADDING_CHAR 'X' // Character used for padding in 16-bit and 32-bit checksums

/**
 * Prints text in 80-character lines for cleaner formatting.
 *
 * @param text  Input string to be displayed.
 */
void printFormattedLines(const char *text)
{
    for (int i = 0; i < strlen(text); i++)
    {
        if (i % LINE_LENGTH == 0) // Insert newline after every 80 characters
            printf("\n");
        putchar(text[i]);
    }
}

/**
 * Computes an 8-bit checksum by summing the ASCII values of each character.
 * Only the last 8 bits are kept to ensure the correct checksum size.
 *
 * @param data  Input string to compute checksum for.
 * @return      8-bit checksum value.
 */

unsigned long computeChecksum8(const char *data)
{
    unsigned long checksum = 0;
    int length = strlen(data);

    for (int i = 0; i < length; i++)
    {
        checksum += (unsigned char)data[i]; // Accumulate ASCII values
    }

    return checksum & 0xFF; // Mask to 8-bit to ensure correct size
}

/**
 * Computes a 16-bit checksum by processing two bytes at a time.
 * If the input length is odd, an 'X' is added to make it even.
 *
 * @param data  Input string to compute checksum for.
 * @return      16-bit checksum value.
 */
unsigned long computeChecksum16(const char *data)
{
    unsigned long checksum = 0;
    int length = strlen(data);

    // Ensure the length is even by padding if necessary
    if (length % 2 != 0)
    {
        length++; // Increase length to accommodate the extra padding byte
    }

    for (int i = 0; i < length; i += 2)
    {
        unsigned char high = (unsigned char)data[i];                                            // First byte (high byte)
        unsigned char low = (i + 1 < strlen(data)) ? (unsigned char)data[i + 1] : PADDING_CHAR; // Second byte (low byte or padding)
        checksum += (high << 8) | low;                                                          // Combine two bytes into a 16-bit word
    }

    return checksum & 0xFFFF; // Mask to 16-bit to ensure correct size
}

/**
 * Computes a 32-bit checksum by processing four bytes at a time.
 * If the input length is not a multiple of 4, it pads with 'X'.
 *
 * @param data  Input string to compute checksum for.
 * @return      32-bit checksum value.
 */
unsigned long computeChecksum32(const char *data)
{
    unsigned long checksum = 0;
    int length = strlen(data);

    // Ensure the length is a multiple of 4 by padding if necessary
    while (length % 4 != 0)
    {
        length++; // Increase length to match 4-byte alignment
    }

    for (int i = 0; i < length; i += 4)
    {
        // Process four bytes at a time, using 'X' for padding if needed
        unsigned char byte1 = (unsigned char)data[i];
        unsigned char byte2 = (i + 1 < strlen(data)) ? (unsigned char)data[i + 1] : PADDING_CHAR;
        unsigned char byte3 = (i + 2 < strlen(data)) ? (unsigned char)data[i + 2] : PADDING_CHAR;
        unsigned char byte4 = (i + 3 < strlen(data)) ? (unsigned char)data[i + 3] : PADDING_CHAR;

        // Combine four bytes into a 32-bit word
        checksum += (byte1 << 24) | (byte2 << 16) | (byte3 << 8) | byte4;
    }

    return checksum & 0xFFFFFFFF; // Mask to 32-bit to ensure correct size
}

int main(int argumentCount, char **argumentValues)
// argumentCount: Holds the total number of arguments passed, including the program name.
// argumentValues: An array of character pointers (strings) storing the arguments that were passed by the user.
{
    FILE *file;                      // File pointer to handle file operations
    char *buffer, ch;                // Buffer to store file contents, ch for reading characters
    unsigned long checksum = 0;      // Stores the calculated checksum value
    int index = 0, checksumBits = 0; // Index for buffer tracking, checksumBits for storing input bit size

    // Validate input arguments
    if (argumentCount != 3)
    {
        fprintf(stderr, "Usage: %s <filename> <8|16|32>\n", argumentValues[0]);
        return -1; // Exit program if argument count is incorrect
    }

    // Validate checksum size
    checksumBits = atoi(argumentValues[2]); // ASCII to Integer: Convert the string argument ("8", "16", or "32") to an integer value.
    if (!(checksumBits == 8 || checksumBits == 16 || checksumBits == 32))
    {
        fprintf(stderr, "Valid checksum sizes are 8, 16, or 32\n");
        return -1; // Exit if input is invalid
    }

    // Attempt to open file
    if (!(file = fopen(argumentValues[1], "r")))
    {
        fprintf(stderr, "Error: Unable to open file \"%s\"\n", argumentValues[1]);
        return -1; // Exit if file cannot be opened
    }

    // Allocate memory and read file contents
    buffer = malloc(sizeof(char) * MAX_BUFFER);
    if (!buffer)
    {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return -1;
    }

    // Read file contents into buffer
    while (fscanf(file, "%c", &ch) != EOF && index < MAX_BUFFER - 1)
    {
        buffer[index++] = ch; // Store each character in buffer
    }
    buffer[index] = '\0'; // Null-terminate the buffer

    // Close file
    fclose(file);

    // Apply necessary padding for 16-bit or 32-bit checksums
    if (checksumBits == 16 && (strlen(buffer) % 2))
        strcat(buffer, "X");
    else if (checksumBits == 32)
        while (strlen(buffer) % 4)
            strcat(buffer, "X");

    // Print formatted text output before checksum calculation
    printFormattedLines(buffer);
    printf("\n");

    // Compute and print the checksum based on bit size
    switch (checksumBits)
    {
    case 8:
        checksum = computeChecksum8(buffer);
        printf("%2d bit checksum is %8lx for all %4d chars\n", checksumBits, checksum & 0xff, (int)strlen(buffer)); // If all passed, print 8-bit checksum
        break;
    case 16:
        checksum = computeChecksum16(buffer);
        printf("%2d bit checksum is %8lx for all %4d chars\n", checksumBits, checksum & 0xffff, (int)strlen(buffer)); // If all passed, print 16-bit checksum
        break;
    case 32:
        checksum = computeChecksum32(buffer);
        printf("%2d bit checksum is %8lx for all %4d chars\n", checksumBits, checksum & 0xffffffff, (int)strlen(buffer)); // If all passed, print 32-bit checksum
        break;
    }

    // Free allocated memory
    free(buffer);

    return 0;
}

/*=============================================================================
| I, affirm that this program is
| entirely my own work and that I have neither developed my code together with
| any another person, nor copied any code from any other person, nor permitted
| my code to be copied or otherwise used by any other person, nor have I
| copied, modified, or otherwise used programs created by others. I acknowledge
| that any violation of the above terms will be treated as academic dishonesty.
+=============================================================================*/
