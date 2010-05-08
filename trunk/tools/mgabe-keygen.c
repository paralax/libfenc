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
// #define MAX_ATTRIBUTES 50
/* will this be enough */
#define KEYSIZE_MAX 4096
#define SIZE 2048
#define SESSION_KEY_LEN 16
#define DEFAULT_KEYFILE "private.key"
char *attributes[MAX_CIPHERTEXT_ATTRIBUTES];
int attributes_len = 0;
char *public_params_file = "public.param";
char *secret_params_file = "master_secret.param";
void report_error(char* action, FENC_ERROR result);
void print_help(void);
void print_buffer_as_hex(uint8* data, size_t len);
void parse_attributes(char *input);
void generate_keys(char *outfile);

/* Description: mgabe-keygen takes the outfile to write the users keys, and the .
 
 */
int main (int argc, char* argv[]) {
	int oflag = FALSE, aflag = FALSE;
	char *keyfile = NULL, *string = NULL;
	int  c;	
	opterr = 0;
	
	while ((c = getopt (argc, argv, "a:o:h")) != -1) {
	
	switch (c)
	  {
		case 'a': // retrieve attributes from user 
			  aflag = TRUE;
			  printf("Generating list of attributes....\n");
			  string = strdup(optarg);
			  parse_attributes(string);
			  break;
		case 'o':
			  oflag = TRUE;
			  keyfile = strdup(optarg);
			  break;
		case 'h':
			  print_help();
			  exit(1);			  
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
	
	/* attribute list required */
	if(aflag == FALSE) {
		fprintf(stderr, "Attributes list required to generate user's key!\n");
		print_help();
		exit(1);
	}

	/* use default file name if not set */
	if(oflag == FALSE) {
		keyfile = DEFAULT_KEYFILE;
	}

	printf("Generating your private-key...\n");
	generate_keys(keyfile);

	free(string);
	free(keyfile);
	// free attribute list 
	for (c = 0; c < attributes_len; c++) {
		free(attributes[c]);
	}	
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

void print_buffer_as_hex(uint8* data, size_t len)
{
	int i;
	
	for (i = 0; i < len; i++) {
		printf("%02x ", data[i]);
	}
	printf("\n");
}

void parse_attributes(char *input)
{
	printf("%s\n", input);
	char *token = strtok(input, ",");
	int ctr = 0, i = 0;
	
	while (token != NULL) {		
		if((attributes[ctr] = malloc(MAX_ATTRIBUTE_STR)) != NULL) {
			memset(attributes[ctr], 0, MAX_ATTRIBUTE_STR);
			strncpy(attributes[ctr], token, MAX_ATTRIBUTE_STR);			
			token = strtok(NULL, ",");
			ctr++;
		}
		
		if(ctr >= MAX_CIPHERTEXT_ATTRIBUTES) /* if we've reached max attributes */
			break;
	}
	
	attributes_len = ctr;
	for (i = 0; i < attributes_len; i++) {
		printf("Attribute '%i' = '%s'\n", i, attributes[i]);
	}
	return;
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
	fenc_key key2;
	FILE *fp;
	char c;
	size_t pub_len = 0, sec_len = 0;
	size_t serialized_len = 0;
	uint8 public_params_buf[SIZE];
	uint8 secret_params_buf[SIZE];
	// char session_key[SESSION_KEY_LEN];
	uint8 output_str[200];
	size_t output_str_len = 0;
	// size_t session_key_len;
	
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
	memset(&key2, 0, sizeof(fenc_key));

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

	uint8 *bin_secret_buf = NewBase64Decode((const char *) secret_params_buf, sec_len, &serialized_len);
	result = libfenc_import_secret_params(&context, bin_secret_buf, serialized_len, NULL, 0);
	report_error("Importing secret parameters", result);
	
	// char *attr[5] = {"ONE", "TWO", "THREE", "FOUR=100"};
	libfenc_create_attribute_list_from_strings(&func_list_input, attributes, attributes_len);
	// libfenc_create_attribute_list_from_strings(&func_list_input, attr, 4);
	fenc_attribute_list_to_buffer((fenc_attribute_list*)(func_list_input.scheme_input), output_str, 200, &output_str_len);
	printf("Attribute list: %s\n", output_str);

	result = libfenc_extract_key(&context, &func_list_input, &key);
	report_error("Extracting a decryption key", result);

	uint8 *buffer = malloc(KEYSIZE_MAX);
	memset(buffer, 0, KEYSIZE_MAX);	
	result = libfenc_export_secret_key(&context, &key, buffer, KEYSIZE_MAX, &serialized_len);
	report_error("Exporting key", result);
	
	size_t keyLength;
	char *secret_key_buf = NewBase64Encode(buffer, serialized_len, FALSE, &keyLength);
	printf("Your secret-key:\t'%s'\nKey-len:\t'%zd'\n", secret_key_buf, serialized_len);	
	
	fp = fopen(outfile, "w");
	if(fp != NULL) {
		fprintf(fp, "%s", secret_key_buf);
	}
	else {
		perror("Error writing private key.");
	}
	fclose(fp);
	
	printf("Buffer contents:\n");
	print_buffer_as_hex(buffer, serialized_len);
/*	result = libfenc_import_secret_key(&context, &key2, buffer, serialized_len);
	report_error("Import secret key", result);
	
	// print out new buffer 
	fenc_key_WatersCP *myKey2 = (fenc_key_WatersCP *) key2.scheme_key;
	size_t serialized_len2;
	uint8 *buffer2 = malloc(KEYSIZE_MAX);
	memset(buffer2, 0, KEYSIZE_MAX);
	result = libfenc_serialize_key_WatersCP(myKey2, buffer2, KEYSIZE_MAX, &serialized_len2);		
	report_error("Serialize user's key", result);
	
	printf("Key-len2: '%zu'\n", serialized_len2);
	printf("Buffer contents 2:\n");
	print_buffer_as_hex(buffer2, serialized_len2);
*/	
	/* Destroy the context. */
	result = libfenc_destroy_context(&context);
	report_error("Destroying context", result);

	/* Shutdown the library. */
	result = libfenc_shutdown();
	report_error("Shutting down library", result);	
		
	/* free buffer */
	free(buffer);
	return;
}
