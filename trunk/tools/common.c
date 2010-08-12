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
	
	ssize_t MAX_LEN = SIZE_MAX * 4;
	if(f != NULL) {
		/* See how big the file is */
		fseek(f, 0L, SEEK_END);
		ssize_t out_len = ftell(f);
		printf("DEBUG: out_len: %zd\n", out_len);
		if(out_len <= MAX_LEN) {
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

int ret_num_bits(int value1)
{
	int j;
	
	for(j = 0; j < BITS; j++) {
		if(value1 < pow(2,j)) {
			double x = (double)j;
			// round to nearest multiple of 4
			int newj = (int) ceil(x/4)*4;
			printf("numberOfBits => '%d'\n", newj);
			return newj;
		}
	}
	return 0;
}

int construct_attribute_list(char *input, char** attributes, size_t *attributes_len)
{
	printf("%s\n", input);
	char *s;
	char *token = strtok(input, ",");
	int ctr = 0, i = 0, j, bin_attrs = 0;
	char tmp[BITS+1];
	
	while (token != NULL) {
		// check if token has '=' operator
		if((s = strchr(token, '=')) != NULL) {
			/* convert to binary form */
			char *attr = malloc(s - token);
			char *value = malloc(strlen(s+1));
			strncpy(attr, token, (s - token));
			strncpy(value, s+1, strlen(s+1));
			/* add code to remove whitespace */
			// printf("attr = '%s', value = '%s'\n", attr, value);
			int v = atoi(value);
			if(v < 0) {
				// report error?
				free(attr);
				free(value);
				fprintf(stderr, "Numerical attribute must be non-negative.\n");
				return -1;
			}
			//printf("attr => '%s'\n", attr);
			bin_attrs = ret_num_bits(v);
			//printf("bin_attrs = '%d'\n", bin_attrs);
			//printf("bit rep of '%d'\n", v);
			/* convert v into n-bit attributes */
		    attributes[ctr] = (char *) malloc(MAX_ATTRIBUTE_STR);
	    	memset(attributes[ctr], 0, MAX_ATTRIBUTE_STR);
			sprintf(attributes[ctr], "%s_flexint_uint", attr);
			ctr++;
			
		    for(j = 0; j < bin_attrs; j++)
		    {
		    	memset(tmp, 'x', BITS);
		    	if (v & (1 << j))
		    		tmp[BITS-j-1] = '1';
				else
					tmp[BITS-j-1] = '0';
		    	attributes[ctr] = (char *) malloc(MAX_ATTRIBUTE_STR);
		    	memset(attributes[ctr], 0, MAX_ATTRIBUTE_STR);
		    	sprintf(attributes[ctr], "%s_flexint_%s", attr, tmp);
				//printf("Attribute '%d' = '%s'\n", ctr, attributes[ctr]);
		    	ctr++;
			}
			
			free(attr);
			free(value);
			// move on to next token
			token = strtok(NULL, ",");
		}
		else {
			// else case for regular attributes?
			if((attributes[ctr] = (char *) malloc(MAX_ATTRIBUTE_STR)) != NULL) {
				memset(attributes[ctr], 0, MAX_ATTRIBUTE_STR);
				strncpy(attributes[ctr], token, MAX_ATTRIBUTE_STR);
				token = strtok(NULL, ",");
				ctr++;
			}
		}
		
		if(ctr >= MAX_CIPHERTEXT_ATTRIBUTES) /* if we've reached max attributes */
			break;
	}
	
	*attributes_len = ctr;
	for (i = 0; i < *attributes_len; i++) {
		printf("Attribute '%i' = '%s'\n", i, attributes[i]);
	}
}
