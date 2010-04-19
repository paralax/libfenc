#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <getopt.h>
#include "libfenc.h"
#include "libfenc_group_params.h"
#include "libfenc_ABE_common.h"
#include "libfenc_WatersCP.h"
#include "libfenc_LSSS.h"				
#include "policy_lang.h"
#include <pbc/pbc_test.h>
#include "base64.h"

/* need to specify command line limit on key size */
#define MAX_ATTRIBUTES 100
/* will this be enough */
#define KEYSIZE_MAX 4096
#define SIZE 2048
#define SESSION_KEY_LEN 16
char **attributes = NULL;
int attribute_count = 0;
char *public_params_file = "public.param";
char *secret_params_file = "master_secret.param";
void report_error(char* action, FENC_ERROR result);
void print_help(void);
void parse_attributes(char *input);
void generate_keys(char *outfile);

/* Description: mgabe-keygen takes the outfile to write the users keys, and the .
 
 */
int main (int argc, const char * argv[]) {
	int oflag = FALSE, aflag = TRUE;
	char *outfile = NULL;
	int  c;
	ssize_t cwdsz = 200;
	char cwdbuf[cwdsz];
	char *cwd = getcwd(cwdbuf, cwdsz);
	printf("CWD: %s\n", cwd);
/*	
	opterr = 0;
	
	while ((c = getopt (argc, argv, "o:a:")) != -1) {
	
	switch (c)
	  {
		case 'a':
			  aflag = TRUE;
			  parse_attributes(strdup(optarg));			  
			  break;
		case 'o':
			oflag = TRUE;
			printf("optarg = '%s'\n", optarg);
			break;
		case '?':
			if (optopt == 'o')
				fprintf (stderr, "Option -%o requires an argument.\n", optopt);
			else if (isprint (optopt))
				fprintf (stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf (stderr,
						 "Unknown option character `\\x%x'.\n", optopt);
			return 1;
		default:
				print_help();
			abort ();
		}
	}
*/	
	if(aflag == FALSE) {
		fprintf(stderr, "No attributes to generate key!\n");
		exit(1);
	}
	
	if(oflag == FALSE) {
		outfile = "private.key";
	}
		
	printf("Generating your private-key...\n");
	generate_keys(outfile);
	if(attributes != NULL)
		free(attributes);
	return 0;
}

void print_help(void)
{
	printf("Usage: ./abe-keygen -o key_file -a ATTR1,ATTR2,ATT3,etc\n\n");
}

void report_error(char* action, FENC_ERROR result)
{
	printf("%s...\n\t%s (%d)\n", action, libfenc_error_to_string(result), result);
}

/* must free memory when done */
void parse_attributes(char *input)
{
	printf("%s\n", input);
	char *token = strtok(input, ",");
	int ctr = 0, MAX_CHAR = 30;
	
	attributes = (char**)calloc(sizeof(char**),MAX_ATTRIBUTES);
	if (attributes == NULL) {
		printf("Error allocating filename array\n");
		exit(1);
	}
	
	while (token != NULL) {
		// printf("token %i: %s\n", ctr, token);
		//strncpy(attributes[ctr], token, MAX_CHAR);
		attributes[ctr] = token; 
		token = strtok(NULL, ",");
		ctr++;
	}
	
	attribute_count = ctr;
	for (int i = 0; i < attribute_count; i++) {
		printf("token '%i' = '%s'\n", i, attributes[i]);
	}
	
	free(input);
	// free(attributes);
}

void generate_keys(char *outfile)
{
	FENC_ERROR result;
	fenc_context context;
	fenc_group_params group_params;
	fenc_global_params global_params;
	fenc_function_input func_list_input;
	pairing_t pairing;
	fenc_key key;
	FILE *fp;
	char c;
	ssize_t pub_len = 0, sec_len = 0;
	ssize_t serialized_len = 0;
	uint8 public_params_buf[SIZE];
	uint8 secret_params_buf[SIZE];
	char session_key[SESSION_KEY_LEN], output_str[200];
	int output_str_len = 0;
	size_t session_key_len;
	
	/* Clear data structures. */
	memset(&context, 0, sizeof(fenc_context));
	memset(&group_params, 0, sizeof(fenc_group_params));
	memset(&global_params, 0, sizeof(fenc_global_params));	
	memset(&public_params_buf, 0, SIZE);
	memset(&secret_params_buf, 0, SIZE);
	memset(output_str, 0, 200);
	/* stores user's authorized attributes */
	memset(&func_list_input, 0, sizeof(fenc_function_input));
	/* stores the user's private key */
	memset(&key, 0, sizeof(fenc_key)); 

	/* Initialize the library. */
	result = libfenc_init();
	/* Create a Sahai-Waters context. */
	result = libfenc_create_context(&context, FENC_SCHEME_WATERSCP);
			
	/* Load group parameters from a file. */
	fp = fopen("d224.param", "r");
	if (fp != NULL) {
		libfenc_load_group_params_from_file(&group_params, fp);
		libfenc_get_pbc_pairing(&group_params, pairing);
	} else {
		perror("Could not open parameters file.\n");
		return;
	}
	fclose(fp);
	
	/* Set up the global parameters. */
	result = context.generate_global_params(&global_params, &group_params);
	report_error("Loading global parameters", result);
	
	result = libfenc_gen_params(&context, &global_params);
	report_error("Generating scheme parameters and secret key", result);
		
	printf("Reading the public parameters file = %s\n", public_params_file);	
	/* read file */
	fp = fopen(public_params_file, "r");
	if(fp != NULL) {
		while (TRUE) {
			c = fgetc(fp);
			if(c != EOF) {
				public_params_buf[pub_len] = c;
				pub_len++;
			}
			else {
				break;
			}
		}
	}
	else {
		perror("File does not exist.\n");
		return;
	}
	fclose(fp);

	printf("Reading the secret parameters file = %s\n", secret_params_file);	
	/* read file */
	fp = fopen(secret_params_file, "r");
	if(fp != NULL) {
		while (TRUE) {
			c = fgetc(fp);
			if(c != EOF) {
				secret_params_buf[sec_len] = c;
				sec_len++;
			}
			else {
				break;
			}
		}
	}
	else {
		perror("File does not exist.\n");
		return;
	}	
	fclose(fp);
	
	printf("public params input = '%s'\n", public_params_buf);
	printf("secret params input = '%s'\n", secret_params_buf);
	
	/* base-64 decode */
	uint8 *bin_public_buf = NewBase64Decode((const char *) public_params_buf, pub_len, &serialized_len);
	/* Import the parameters from binary buffer: */
	result = libfenc_import_public_params(&context, bin_public_buf, serialized_len);
	report_error("Importing public parameters", result);

	uint8 *bin_secret_buf = NewBase64Decode(secret_params_buf, sec_len, &serialized_len);
	result = libfenc_import_secret_params(&context, bin_secret_buf, serialized_len, NULL, 0);
	report_error("Importing secret parameters", result);
	
	char *attr[9] = {"ONE", "TWO", "THREE", "FOUR", "FIVE", "SIX", "SEVEN", "EIGHT"};
	libfenc_create_attribute_list_from_strings(&func_list_input, attr, 8);
	fenc_attribute_list_to_buffer((fenc_attribute_list*)(func_list_input.scheme_input), output_str, 200, &output_str_len);
	printf("Attribute list: %s\n", output_str);

	result = libfenc_extract_key(&context, &func_list_input, &key);
	report_error("Extracting a decryption key", result);
	
	fenc_key_WatersCP *myKey = (fenc_key_WatersCP *) key.scheme_key;
//	result = libfenc_serialize_key_WatersCP(myKey, NULL, 0, &serialized_len);	
//	if (result != FENC_ERROR_NONE) { report_error("Computing secret parameter output size", result); }
	char *buffer = malloc(KEYSIZE_MAX);
	result = libfenc_serialize_key_WatersCP(myKey, buffer, KEYSIZE_MAX, &serialized_len);		
	report_error("Serialize user's key", result);
	
	ssize_t keyLength;
	char *secret_key_buf = NewBase64Encode((uint8 *) buffer, serialized_len, FALSE, &keyLength);
	printf("Buffer contents: '%s'\nBuffer length: '%zd'\n", buffer, serialized_len);
	printf("Your secret-key: '%s'\n", secret_key_buf);	
	
	fp = fopen(outfile, "w");
	if(fp != NULL) {
		fprintf(fp, "%s", secret_key_buf);
	}
	else {
		perror("Error writing private key.");
	}
	fclose(fp);
	
	/* Destroy the context. */
	result = libfenc_destroy_context(&context);
	report_error("Destroying context", result);

	/* Shutdown the library. */
	result = libfenc_shutdown();
	report_error("Shutting down library", result);	
		
	free(buffer);
	return;
}
