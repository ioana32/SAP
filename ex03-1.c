#include <stdio.h>
#include <memory.h>
#include <string.h>

int main()
{
	FILE* f;
	char s[] = "This is the new content of the file.txt";
	char buffer[100];
	fpos_t position;

	f = fopen("file.txt", "w+");

	size_t n = fwrite(s, sizeof(s), 1, f); 
	//size_t n = fwrite(s, 1, sizeof(s), f); 
	printf("Result of fwrite as number of blocks: %d\n", n);

	fgetpos(f, &position);
	printf("Current position: %lld bytes from the file beginning\n", position);

	if (fseek(f, 0, SEEK_SET)) return 1; 

	fgetpos(f, &position);
	printf("Current position: %lld bytes from the file beginning\n", position);

	memset(&buffer, 0x00, sizeof(buffer));
	//n = fread(&buffer, sizeof(s), 1, f);
	n = fread(&buffer, strlen(s) + 1, 1, f);
	printf("Result of fread as number of blocks: %d\n", n);
	fgetpos(f, &position);
	printf("Current position: %lld bytes from the file beginning\n", position);

	if (fseek(f, 0, SEEK_SET)) return 1; // or fsetpos(f, &position); where position initialized to 0 before

	memset(&buffer, 0x00, sizeof(buffer));
	n = fread(&buffer, 1, strlen(s) + 1, f); 
	printf("Result of fread as number of blocks: %d\n", n);
	fgetpos(f, &position);
	printf("Current position: %lld bytes from the file beginning\n", position);

	printf("%s\n", buffer);

	fclose(f);

	return(0);
}