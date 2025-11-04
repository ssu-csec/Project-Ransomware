#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>

int main(int argc, char *argv[])
{
	/* Declare variables */
	HCRYPTPROV hCryptProv;
	BYTE pbData[16];

	/* Display a help message */
	if (argc == 2 && (!strcmp(argv[1], "/?") || !strcmp(argv[1], "-?") || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")))
	{
		printf("Generates and displays a random hex string 16 characters long\n");
		printf("\n");
		printf("GENRANDOM\n");
		exit(1);
	}

	if (CryptAcquireContext(
		&hCryptProv,
		NULL,
		(LPCWSTR)L"Microsoft Base Cryptographic Provider v1.0",
		PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT))
	{
		if (CryptGenRandom(
			hCryptProv,
			16,
			pbData))
		{
			printf("Random sequence generated: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n",
				pbData[0], pbData[1], pbData[2], pbData[3], pbData[4], pbData[5], pbData[6], pbData[7], pbData[8],
				pbData[9], pbData[10], pbData[11], pbData[12], pbData[13], pbData[14], pbData[15]);
			if (CryptReleaseContext(hCryptProv, 0))
			{
				return 0;
			}
			else
			{
				printf("Error during CryptReleaseContext.\n");
				return 4;
			}
		}
		else
		{
			if (CryptReleaseContext(hCryptProv, 0))
			{
				printf("Error during CryptGenRandom.\n");
				return 2;
			}
			else
			{
				printf("Error during CryptReleaseContext.\n");
				return 3;
			}
		}
	}
	else
	{
		printf("Error during CryptAcquireContext!\n");
		return 1;
	}
}