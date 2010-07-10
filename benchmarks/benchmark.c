#include "common.h"
#include <time.h>
#include <fenc/libfenc_LSW.h>

char *abe_priv_keyfile = "private.key";
// different schemes to benchmark under
void benchmark_schemes(void);
int get_key(char *keyfile, fenc_context *context, fenc_key *secret_key);
void apply_LSW(void);
void apply_WatersCP(char *policy, char *outfile);
void apply_WatersSimpleCP(void);

int main(int argc, char *argv[])
{
	// argv[1] => policy string
	// argv[2] => scheme type
	// argv[3] => outfile name
	if(argc != 4) {
		printf("Usage %s: [ policy ] [ scheme ] [ outfile ]", argv[0]);
		exit(1);
	}
	
	char *string = argv[1];
	char *scheme = argv[2];
	char *outfile = argv[3];
	
	// setup getopt for now hardcode
	printf("Benchmarking libfenc ABE schemes...\n");
	if(strcmp(scheme, "WCP") == 0) {
		apply_WatersCP(string, outfile);
	}
	else if(strcmp(scheme, "WSCP") == 0) {
		// apply_WatersSimpleCP(string, outfile);
	}	
	else if(strcmp(scheme, "LSW") == 0) {
		// apply_LSW(string, outfile);
	}
	else {
		// print error...
	}


	return 0;
}

/* inputs => 'scheme' and a string which represents policy or attributes dependent on the scheme */
/* output => # leaves and decryption time. In addition, an well defined output format of the results */
void benchmark_schemes(void)
{
	FENC_ERROR result;	
}

int get_key(char *keyfile, fenc_context *context, fenc_key *secret_key)
{
	FENC_ERROR result;
	char *keyfile_buf = NULL;
	size_t key_len;
	FILE *fp;
	fp = fopen(keyfile, "r");
	if(fp != NULL) {
		if((key_len = read_file(fp, &keyfile_buf)) > 0) {
			// printf("\nYour private-key:\t'%s'\n", keyfile_buf);
			size_t keyLength;
			uint8 *bin_keyfile_buf = NewBase64Decode((const char *) keyfile_buf, key_len, &keyLength);
			
#ifdef DEBUG
			/* base-64 decode user's private key */
			printf("Base-64 decoded buffer:\t");
			print_buffer_as_hex(bin_keyfile_buf, keyLength);
#endif			
			result = libfenc_import_secret_key(context, secret_key, bin_keyfile_buf, keyLength);
			report_error("Importing secret key", result);
			free(keyfile_buf);
			free(bin_keyfile_buf);
		}			
	}
	else {
		fprintf(stderr, "Could not load input file: %s\n", keyfile);
		return FALSE;
	}
	fclose(fp);
	
	return TRUE;
}

void apply_WatersCP(char *policy, char *outfile) 
{
	FENC_ERROR result;
	fenc_context context;
	fenc_group_params group_params;
	fenc_global_params global_params;
	fenc_function_input policy_input;
	fenc_ciphertext ciphertext;
	fenc_key master_key;
	pairing_t pairing;
	FILE *fp;
	char *public_params_buf = NULL;
	char session_key[SESSION_KEY_LEN];
	fenc_plaintext rec_session_key;
	size_t serialized_len;
	clock_t start, stop;
	
	memset(&context, 0, sizeof(fenc_context)); 
	memset(&group_params, 0, sizeof(fenc_group_params));
	memset(&global_params, 0, sizeof(fenc_global_params));	
	memset(&ciphertext, 0, sizeof(fenc_ciphertext));
	memset(&master_key, 0, sizeof(fenc_key));
	
	/* Initialize the library. */
	result = libfenc_init();
	report_error("Initializing library", result);
	
	/* Create a Sahai-Waters context. */
	result = libfenc_create_context(&context, FENC_SCHEME_WATERSCP);
	report_error("Creating context for Waters CP scheme", result);
	
	/* Load group parameters from a file. */
	fp = fopen(PARAM, "r");
	if (fp != NULL) {
		libfenc_load_group_params_from_file(&group_params, fp);
		libfenc_get_pbc_pairing(&group_params, pairing);
	} else {
		perror("Could not open type-d parameters file.\n");
		return;
	}
	fclose(fp);
	
	/* Set up the global parameters. */
	result = context.generate_global_params(&global_params, &group_params);	
	result = libfenc_gen_params(&context, &global_params);
	
	/* Set up the publci parameters */
	fp = fopen(public_params_file, "r");
	if(fp != NULL) {
		size_t pub_len = read_file(fp, &public_params_buf);
		/* base-64 decode */
		uint8 *bin_public_buf = NewBase64Decode((const char *) public_params_buf, pub_len, &serialized_len);
		/* Import the parameters from binary buffer: */
		result = libfenc_import_public_params(&context, bin_public_buf, serialized_len);
		report_error("Importing public parameters", result);
		free(public_params_buf);
		free(bin_public_buf);
	}
	else {
		perror("Could not open public parameters\n");
		return;
	}
	fclose(fp);
		
	/* encrypt under given policy */ 
	fenc_attribute_policy *parsed_policy = (fenc_attribute_policy *) malloc(sizeof(fenc_attribute_policy));
	memset(parsed_policy, 0, sizeof(fenc_attribute_policy)); 

	fenc_policy_from_string(parsed_policy, policy);
	policy_input.input_type = FENC_INPUT_NM_ATTRIBUTE_POLICY;
	policy_input.scheme_input = (void *) parsed_policy;
	
	/* store the policy for future reference? */
	char policy_str[512];
	memset(policy_str, 0, 512);
	fenc_attribute_policy_to_string(parsed_policy->root, policy_str, 512);	
	
	/* perform encryption */
	result = libfenc_kem_encrypt(&context, &policy_input, SESSION_KEY_LEN, (uint8 *) session_key, &ciphertext);	
	
	printf("Decryption key:\t");
	print_buffer_as_hex(session_key, SESSION_KEY_LEN);
	
	/* now perform decryption with session key */
	printf("Successful import => '%d'\n", get_key(abe_priv_keyfile, &context, &master_key));
	
	fenc_key_WatersCP *key_WatersCP = (fenc_key_WatersCP *) master_key.scheme_key;	
	uint32 num_leaves = prune_tree(parsed_policy->root, &(key_WatersCP->attribute_list));
	
	/* start timer */
	start = clock();
	printf("Starting timer...\n");

	// retrieve decryption key 
	/* Descrypt the resulting ciphertext. */
	result = libfenc_decrypt(&context, &ciphertext, &master_key, &rec_session_key);
/*	if (result == FENC_ERROR_NONE) {
		if (memcmp(rec_session_key.data, session_key, rec_session_key.data_len) != 0) {
			result = FENC_ERROR_UNKNOWN;
		}
	}
*/
	report_error("Decrypting the ciphertext", result);
	
	printf("Recovered session key:\t");
	print_buffer_as_hex(rec_session_key.data, rec_session_key.data_len);	
		
	/* stop timer */
	stop = clock();
	printf("Stopping timer...\n\n");
	double diff = ((double)(stop - start))/CLOCKS_PER_SEC;
	
	
	if(memcmp(rec_session_key.data, session_key, rec_session_key.data_len) == 0) {
		printf("\nDECRYPTION TIME => %f secs.\n", diff);
		printf("NUMBER OF LEAVES => %d\n", num_leaves);		
		printf("POLICY => '%s'\n", policy_str);	
		fp = fopen(outfile, "a");
		fprintf(fp, "TIME=%f:LEAVES=%d:SCHEME=WCP\n", diff, num_leaves);
		fclose(fp);
	}
		
	free(parsed_policy);
	/* Shutdown the library. */
	result = libfenc_shutdown();
	report_error("Shutting down library", result);		
}
