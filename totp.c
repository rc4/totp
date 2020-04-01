/* simple totp generator
 * generates 6 digit code with 30sec step
 * build with -loath, requires liboath from 
 * https://www.nongnu.org/oath-toolkit/ */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <liboath/oath.h>

#define DIGITS 6 /* Length the generated code will be */ 

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s secret\n", argv[0]);
		return 0;
	}

	char *secret;
	size_t secretlen = 0;
	int rc;
	char otp[10];
	time_t now;

	rc = oath_init();
	if (rc != OATH_OK) {
		fprintf(stderr, "oath_init failed: %s\n", oath_strerror(rc));
		return 1;
	}
	
	rc = oath_base32_decode(argv[1], strlen(argv[1]), 
							&secret, &secretlen);
	if(rc != OATH_OK) {
		fprintf(stderr, "bad secret value: %s\n", oath_strerror(rc));
		return 1;
	}
	
	now = time(NULL);
	rc = oath_totp_generate(secret, secretlen, now,
							OATH_TOTP_DEFAULT_TIME_STEP_SIZE,
							OATH_TOTP_DEFAULT_START_TIME,
							DIGITS, otp);
	if (rc != OATH_OK) {
		fprintf(stderr, "totp generation failed: %s\n", oath_strerror(rc));
		return 2;
	}
	else
		printf ("Code: %s\n", otp);
	
	memset(secret, 0, sizeof(secret));
	free(secret);
	
	rc = oath_done();
	if (rc != OATH_OK)
		return 255; /* wtf? */
		
	return 0;
}
