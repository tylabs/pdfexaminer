/*         
 *   emucheck
 *
 *   shell code detection through emulation using libemu
 *
 *   
 *   Compiling:
 *   gcc -Wall -I/opt/libemu/include/ -L/opt/libemu/lib/libemu -o emucheck emu.c -lemu
 *
 *   Usage env prep:
 *   LD_LIBRARY_PATH=/opt/libemu/lib/libemu
 *   export LD_LIBRARY_PATH
 * */

#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <emu/emu.h>
#include <emu/emu_shellcode.h>
#include <emu/emu_memory.h>




struct emu *emu;


void check_emu (uint8_t *data, int size)
{

		if ( emu_shellcode_test(emu, (uint8_t *)data, size) >= 0 )
		{
			fprintf(stdout, "SHELLCODE DETECTED\n");
		} else {
			fprintf(stdout, "CLEAN\n");
		}


	emu_memory_clear(emu_memory_get(emu));
	return ;
}


int main (int argc, const char *argv[])
{
	FILE *file;
	uint8_t *buffer;
	unsigned long fileLen;

	if (argc == 1)
	{
		printf("usage %s <filename to test for shellcode>\n", argv[0]);
		return -1;
	}

	emu = emu_new();


	//Open file
	file = fopen(argv[1], "rb");
	if (!file)
	{
		fprintf(stderr, "Unable to open file %s\n", argv[1]);
		return 1;
	}
	
	//Get file length
	fseek(file, 0, SEEK_END);
	fileLen=ftell(file);
	fseek(file, 0, SEEK_SET);


	//Allocate memory
	buffer= (uint8_t *) malloc(fileLen+1);
	if (!buffer)
	{
		fprintf(stderr, "Memory error!");
                                fclose(file);
		return 1;
	}

	//Read file contents into buffer
	fread(buffer, fileLen, 1, file);

	fclose(file);

	check_emu (buffer, fileLen);
	free(buffer);

	emu_free(emu);
	return 0;
}
