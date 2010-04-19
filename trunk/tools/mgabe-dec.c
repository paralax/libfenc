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
#include "libfenc_LSSS.h"
#include "libfenc_WatersCP.h"
#include "policy_lang.h"
#include <pbc/pbc_test.h>
#include "base64.h"
#include "openssl/aes.h"
#include "openssl/sha.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/rand.h"

/* test encryption of "hello world" under policy of "ONE or TWO" */
char *abeblob = "AgAAABAAAAACAAAAKE9ORSBvciBUV08pAHcaXp9A+whfiBydC2z1NRzTmXlklACTzPQNQZMBVJZR0PiGl58huj6y9t73BN9okqIAVJZR0PiGlw8QRMl6IYHe2r7klZrKIPGc28qH0av7KGLzmzkATkXGKyTcOKK9PD+bbOFXvEXOE30knweDcWhG1AKR7xmQv/Pz0B5udSc38UhO2OP1rl/UmBXXpvgFQf/pG+wmaSprvgGviSBRT5Aat1YEO1uRhDywACCNVMQI/YSn1sdTsLUqOWFZ2UANACCNVMQI/YQLw7BNdnb1I2Ly4HUilyFS4/bGR3jfRfWmY5laAYHriOwjQFUjHCC5uFPsuUJOc9g3qsBRyhEInXM4Yj8Y7tkqbx+1P7H+3Ts7n6ugRwlpW8QEAk9gf/H2dpHpbqHuBPRs1nkaTo93YlCmA37tSzOETgA=</ABE><EncryptedData>B44Mo+L2vuu6r+o=";
char *aesblob = "B44Mo+L2vuu6r+o=";

#define MAX_ATTRIBUTES 100
#define SIZE 2048
#define SESSION_KEY_LEN 16
char *public_params_file = "public.param";
char *secret_params_file = "master_secret.param";
void report_error(char* action, FENC_ERROR result);
void print_help(void);
void cpabe_decrypt(char *inputfile, char *keyfile);
void print_buffer_as_hex(uint8* data, size_t len);

/* Description: mgabe-keygen takes the outfile to write the users keys, and the .
 
 */
int main (int argc, const char * argv[]) {
	int dflag = TRUE, kflag = TRUE;
	char *file = "input.txt", *key = "private.key";
	int c;
	
	opterr = 0;
/*	
	while ((c = getopt (argc, argv, "d:k:")) != -1) {
		
		switch (c)
		{
			case 'd': // file that holds encrypted data 
				dflag = TRUE;				
				file = optarg;
				printf("encrypted file = '%s'\n", key);
				break;
			case 'k': // input of private key 
				kflag = TRUE;
				key = optarg;
				printf("private-key file = '%s'\n", file);
				break;
			case 'h': // print usage 
				print_help();
				exit(0);
				break;
			case '?':
				if (optopt == 'd' || optopt == 'k')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
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
	if(dflag == FALSE) {
		fprintf(stderr, "No file to decrypt!\n");
		print_help();
		exit(1);
	}
	
	if(kflag == FALSE) {
		fprintf(stderr, "Decrypt without a key? c'mon!\n");
		print_help();
		exit(1);
	}
	
	
	printf("Ok. Decrypting data.\n");
	cpabe_decrypt(file, key);
	printf("Complete!\n");
	return 0;
}

void print_help(void)
{
	printf("Usage: ./abe-dec -k [ private-key ] -d [ file-to-decrypt ] \n\n");
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


void cpabe_decrypt(char *inputfile, char *keyfile)
{
	FENC_ERROR result;
	fenc_context context;
	fenc_group_params group_params;
	fenc_global_params global_params;
	fenc_ciphertext ciphertext;
	fenc_function_input func_list_input;
	fenc_plaintext aes_session_key;
	fenc_key_WatersCP key;
	pairing_t pairing;
	fenc_key secret_key;
	
	FILE *fp;
	char c;
	int pub_len = 0, sec_len = 0, key_len = 0;
	ssize_t serialized_len = 0;
	uint8 public_params_buf[SIZE];
	uint8 secret_params_buf[SIZE];
	uint8 keyfile_buf[SIZE];
	char session_key[SESSION_KEY_LEN];
	// size_t session_key_len;
	char output_str[200];
	int output_str_len = 200;
	/* Clear data structures. */
	memset(&context, 0, sizeof(fenc_context));
	memset(&group_params, 0, sizeof(fenc_group_params));
	memset(&global_params, 0, sizeof(fenc_global_params));	
	memset(&public_params_buf, 0, SIZE);
	memset(&ciphertext, 0, sizeof(fenc_ciphertext));
	memset(&aes_session_key, 0, sizeof(fenc_plaintext));
	memset(keyfile_buf, 0, SIZE);
	memset(public_params_buf, 0, SIZE);
	memset(output_str, 0, output_str_len);
	// memset(&key, 0, sizeof(fenc_key_WatersCP));
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
	// report_error("Generating scheme parameters and secret key", result);
	
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
	// printf("public params input = '%s'\n", public_params_buf);
	
	/* base-64 decode public parameters */
	uint8 *bin_public_buf = NewBase64Decode((const char *) public_params_buf, pub_len, &serialized_len);
	// printf("public params binary = '%s'\n", bin_public_buf);
	
	/* Import the parameters from binary buffer: */
	result = libfenc_import_public_params(&context, bin_public_buf, serialized_len);
	report_error("Importing public parameters", result);
	
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
	
	uint8 *bin_secret_buf = NewBase64Decode(secret_params_buf, sec_len, &serialized_len);
	result = libfenc_import_secret_params(&context, bin_secret_buf, serialized_len, NULL, 0);
	report_error("Importing secret parameters", result);
	
	/* read input key file (PRIVATE KEY)
	printf("keyfile => '%s'\n", keyfile);
	fp = fopen(keyfile, "r");
	if(fp != NULL) {
		while (TRUE) {
			c = fgetc(fp);
			// printf("%c", c);
			if(c != EOF) {
				keyfile_buf[key_len] = c;
				key_len++;
			}
			else {
				break;
			}
		}		
	}
	else {
		printf("File does not exist.\n");
		return;
	}
	fclose(fp);
	
	printf("\nYour private-key: '%s'\n", keyfile_buf); */
	
	/* base-64 decode user's private key 
	ssize_t keyLength;
	uint8 *bin_keyfile_buf = NewBase64Decode((const char *) keyfile_buf, key_len, &keyLength);
	printf("base-64 decoded: '%s'\n", bin_keyfile_buf, keyLength); */
	
	/* deserialize key 	
	result = libfenc_deserialize_key_WatersCP(&key, bin_keyfile_buf, keyLength);
	report_error("Deserialize private key", result); */
	
	
	/* BEGIN TEST: Extract a decryption key. */
	
	/* Retrieve secret params */
	
	
	/* stores user's authorized attributes */
	memset(&func_list_input, 0, sizeof(fenc_function_input));
	char *attr[9] = {"ONE", "TWO", "THREE", "FOUR", "FIVE", "SIX", "SEVEN", "EIGHT"};
	libfenc_create_attribute_list_from_strings(&func_list_input, attr, 8);
	fenc_attribute_list_to_buffer((fenc_attribute_list*)(func_list_input.scheme_input), output_str, 200, &output_str_len);
	printf("Attribute list: %s\n", output_str);
	
	result = libfenc_extract_key(&context, &func_list_input, &secret_key);
	report_error("Extracting a decryption key", result);	
	
	// result = libfenc_import_secret_key(&context, &secret_key, bin_keyfile_buf, keyLength);
	// report_error("Importing secret key", result);
	ssize_t abeLength;
	char *data = NewBase64Decode((const char *) abeblob, strlen(abeblob), &abeLength);
	ciphertext.data = data;
	ciphertext.data_len = abeLength;
	ciphertext.max_len = abeLength;
	
	/* Descrypt the resulting ciphertext. */
	result = libfenc_decrypt(&context, &ciphertext, &secret_key, &aes_session_key);
	if (result == FENC_ERROR_NONE) {
		if (memcmp(aes_session_key.data, session_key, aes_session_key.data_len) != 0) {
			result = FENC_ERROR_UNKNOWN;
		}
	}
	report_error("Decrypting the ciphertext", result);
	
	printf("\tDecrypted session key is: ");
	print_buffer_as_hex(aes_session_key.data, aes_session_key.data_len);

	/* use the PSK to encrypt using openssl functions here */
	
	
	/* base-64 both ciphertext and write to the stdout -- in XML? */
		
	/* Destroy the context. */
	result = libfenc_destroy_context(&context);
	report_error("Destroying the encryption context", result);	
	
	/* Shutdown the library. */
	result = libfenc_shutdown();
	report_error("Shutting down library", result);
	return;
}

