#include "common.h"

void report_error(char* action, FENC_ERROR result)
{
	printf("%s...\n\t%s (%d)\n", action, libfenc_error_to_string(result), result);
}

void print_buffer_as_hex(uint8* data, size_t len)
{
	size_t i;
	
	for (i = 0; i < len; i++) {
		printf("%02x ", data[i]);
	}
	printf("\n");
}

ssize_t read_file(FILE *f, char** out) {
	
	if(f != NULL) {
		/* See how big the file is */
		fseek(f, 0L, SEEK_END);
		ssize_t out_len = ftell(f);
		printf("out_len: %zd\n", out_len);
		if(out_len <= SIZE_MAX) {
			/* allocate that amount of memory only */
			if((*out = (char *) malloc(out_len+1)) != NULL) {
				fseek(f, 0L, SEEK_SET);
				fread(*out, sizeof(char), out_len, f);
				return out_len;
			}
		}
	}
	return 0;
}

