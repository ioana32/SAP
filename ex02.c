#include <stdio.h>

#define MACRO_1
#define MACRO_2
#define A_VALUE_1 3

//#define A 1
#define A 0 

#define macro1(s) # s

#define macro2(s1, s2) s1 ## s2

int main()
{
	unsigned char a, b, bc;

#if(A == 0x01)
	a = A_VALUE_1;
#else
	a = 4;
#endif

	b = 2;

#undef MACRO_1

#if(A == 0x01)
	#ifdef MACRO_1
		char s[] = macro1(Ionescu); 
		printf("%s\n", s);
	#endif
#else	
	#ifdef MACRO_2
		macro2(b, c) = a + b; // bc = a + b;
		// macro2(a, b) = 0; // compiling errors because there is no def for ab
		printf("%d\n", macro2(b, c)); // printf("%d\n", bc);
	#endif
#endif

	return 0;
}