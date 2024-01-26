#include <stdio.h>


int main() {
	FILE* fp;
	fpos_t position, position_after;

	fp = fopen("file.txt", "w+");
	fgetpos(fp, &position);
	fputs("Hello, World!", fp);

	fgetpos(fp, &position_after);
	printf("Current position after 1st fputs: %lld\n", position_after);

	//fsetpos(fp, &position); // positioning on the beginning of the file
	fsetpos(fp, &position_after); // positioning at the end of file (one single write before for "Hello, World!")
	fputs("This is going to override previous content.", fp);

	fgetpos(fp, &position_after);
	printf("Current position after 2nd fputs: %lld\n", position_after); // actually, the size of the file

	fclose(fp);

	return(0);
}