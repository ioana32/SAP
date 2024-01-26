#include <stdio.h>
#include <memory.h>

int main()
{
	FILE* f;
	int c;

	f = fopen("file.txt", "r");

	//while (1)
	//{
	//	c = fgetc(f);
	//	if (feof(f))
	//	{
	//		break;
	//	}
	//	printf("%c", c);
	//}

	char buffer[256], * pb;
	while (1)
	{
		pb = fgets(buffer, sizeof(buffer), f); // pb points to the beginning of buffer if the read is successful
		printf("%s", buffer);
		if (feof(f))
		{
			break;
		}
		memset(buffer, 0, sizeof(buffer));
	}

	fclose(f);

	return 0;
}