#include "common.h"

/* Description: mgabe-setup takes no arguments and simply reads in the global parameters from the filesystem,
 and generates the public parameters (or public key) and the master secret parameters (or master secret key).
 
 It serializes and writes to disk the public parameters and the master secret key.
 
 */
int main (int argc, char * argv[]) {
	FENC_ERROR result;
	fenc_context context;
	fenc_group_params group_params;
	fenc_global_params global_params;
	pairing_t pairing;
	FILE *fp;
	size_t serialized_len = 0;
	uint8* public_params_buf = NULL;
	uint8* secret_params_buf = NULL;
	
	/* Clear data structures. */
	memset(&context, 0, sizeof(fenc_context));
	memset(&group_params, 0, sizeof(fenc_group_params));
	memset(&global_params, 0, sizeof(fenc_global_params));
	
	/* Initialize the library. */
	result = libfenc_init();
	report_error("Initializing library", result);	
	
	// insert code here...
    printf("Generating master ABE system parameters...\n");
	/* Create a Sahai-Waters context. */
	result = libfenc_create_context(&context, FENC_SCHEME_WATERSCP);
	report_error("Creating a Waters-CP encryption context", result);
	
	/* Load group parameters from a file. */
	fp = fopen("d224.param", "r");
	if (fp != NULL) {
		libfenc_load_group_params_from_file(&group_params, fp);
		libfenc_get_pbc_pairing(&group_params, pairing);
	} else {
		perror("Could not open parameters file.\n");
		exit(1);
	}
	fclose(fp);
	
	/* Set up the global parameters. */
	result = context.generate_global_params(&global_params, &group_params);
	report_error("Loading global parameters", result);

	result = libfenc_gen_params(&context, &global_params);
	report_error("Generating scheme parameters and secret key", result);
	
	/* Serialize the public parameters into a buffer */
	result = libfenc_export_public_params(&context, NULL, 0, &serialized_len, FALSE);
	if (result != FENC_ERROR_NONE) { report_error("Computing public parameter output size", result); }
	if((public_params_buf = malloc(serialized_len)) == NULL) {
		perror("malloc failed.");
		exit(1);
	}
	/* Export public parameters to buffer with the right size */
	result = libfenc_export_public_params(&context, public_params_buf, serialized_len, &serialized_len, FALSE);
	report_error("Exporting public parameters", result);

	printf("Base-64 encoding public parameters...\n");
	size_t publicLength;
	char *publicBuffer = NewBase64Encode(public_params_buf, serialized_len, FALSE, &publicLength);
	printf("'%s'\n", publicBuffer);
			
	/* base-64 encode the pub params and write to disk */
	fp = fopen(public_params_file, "w");
	if(fp != NULL) {
		fprintf(fp, "%s", publicBuffer);
	}
	fclose(fp);
	
	/*result = libfenc_import_public_params(&context, public_params_buf, serialized_len);
	report_error("Re-importing public parameters", result); */

	
	/* Serialize the secret parameters into a buffer (not strictly necessary, just a test). */
	result = libfenc_export_secret_params(&context, NULL, 0, &serialized_len, NULL, 0);
	if (result != FENC_ERROR_NONE) { report_error("Computing secret parameter output size", result); }
	if((secret_params_buf = malloc(serialized_len)) == NULL) {
		perror("malloc failed.");
		exit(1);
	}
	result = libfenc_export_secret_params(&context, secret_params_buf, serialized_len, &serialized_len, NULL, 0);
	report_error("Exporting secret parameters", result);
	
	printf("Base-64 encoding public parameters...\n");
	size_t secretLength;
	char *secretBuffer = NewBase64Encode(secret_params_buf, serialized_len, FALSE, &secretLength);
	printf("'%s'\n", secretBuffer);
	
	/* base-64 encode the pub params and write to disk */
	fp = fopen(secret_params_file, "w");
	if(fp != NULL) {
		fprintf(fp, "%s", secretBuffer);
	}
	fclose(fp);
	
	/* Destroy the context. */
	result = libfenc_destroy_context(&context);
	report_error("Destroying context", result);
	
	/* Shutdown the library. */
	result = libfenc_shutdown();
	report_error("Shutting down library", result);	
	
	free(public_params_buf);
	free(publicBuffer);
	free(secretBuffer);
    return 0;
}


