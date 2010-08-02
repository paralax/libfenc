#include <ctype.h>
#include <getopt.h>
#include <math.h>
#include "common.h"

#define DEFAULT_KEYFILE "private.key"
char *attributes[MAX_CIPHERTEXT_ATTRIBUTES];
char *policy = NULL;
int attributes_len = 0;
int parse_attributes(char *input);
void generate_keys(char *outfile, FENC_SCHEME_TYPE scheme, char *secret_params, char *public_params);
/* Description: mgabe-keygen takes the outfile to write the users keys, and the .
 
 */
int main (int argc, char* argv[]) {
	int oflag = FALSE, aflag = FALSE, pflag = FALSE;
	char *keyfile = NULL, *string = NULL;
	int  c,err;
	FENC_SCHEME_TYPE mode = FENC_SCHEME_NONE;
	char *secret_params = NULL, *public_params = NULL;
	opterr = 0;
	
	while ((c = getopt (argc, argv, "a:o:m:p:h")) != -1) {
	
	switch (c)
	  {
		case 'a': // retrieve attributes from user 
			  aflag = TRUE;
			  printf("Generating list of attributes....\n");
			  string = strdup(optarg);
			  err = parse_attributes(string);
			  free(string);
			  break;
		case 'p':
			  pflag = TRUE;
			  policy = strdup(optarg);
			  break;
		case 'o':
			  oflag = TRUE;
			  keyfile = optarg;
			  break;
		case 'm': 
			  if (strcmp(optarg, SCHEME_LSW) == 0) {
				  printf("Generating private key for Lewko-Sahai-Waters KP scheme...\n");
				  mode = FENC_SCHEME_LSW;
				  secret_params = SECRET_FILE".kp";
				  public_params = PUBLIC_FILE".kp";
			  }
			  else if(strcmp(optarg, SCHEME_WCP) == 0) {
				  printf("Generating private key for Waters CP scheme...\n");
				  mode = FENC_SCHEME_WATERSCP;
				  secret_params = SECRET_FILE".cp";
				  public_params = PUBLIC_FILE".cp";
			  }
			  else if(strcmp(optarg, SCHEME_WSCP) == 0) {
				  printf("Generating private key for Waters Simple CP scheme...\n");
				  mode = FENC_SCHEME_WATERSSIMPLECP;
				  secret_params = SECRET_FILE".scp";
				  public_params = PUBLIC_FILE".scp";				  
			  }
			  break;
		case 'h':
			  print_help();
			  exit(1);			  
		case '?':
			if (optopt == 'o' )
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
	if(aflag == FALSE && mode == FENC_SCHEME_WATERSCP) {
		fprintf(stderr, "Attributes list required to generate user's key!\n");
		print_help();
		exit(1);
	}
	
	if(pflag == FALSE && mode == FENC_SCHEME_LSW) {
		fprintf(stderr, "Policy required to generate user's key under "SCHEME_LSW" scheme\n");
		print_help();
		exit(1);
	}

	/* use default file name if not set */
	if(oflag == FALSE) {
		keyfile = DEFAULT_KEYFILE;
	}

	if(mode == FENC_SCHEME_NONE) {
		fprintf(stderr, "Please specify a scheme type\n");
		print_help();
		goto cleanup;
	}
	
	
	printf("Generating your private-key...\n");
	generate_keys(keyfile, mode, secret_params, public_params);

cleanup:
/*	if(keyfile != NULL)
		free(keyfile);
 */
	// free attribute list 
	for (c = 0; c < attributes_len; c++) {
		free(attributes[c]);
	}
	return 0;
}

void print_help(void)
{
	printf("Usage: ./abe-keygen -m [ KP,CP or SCP ] -a [ ATTR1,ATTR2,ATT3,etc ] -o [ key file ]\n\n");
}

int parse_attributes(char *input)
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
		    attributes[ctr] = malloc(MAX_ATTRIBUTE_STR);
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
		    	attributes[ctr] = malloc(MAX_ATTRIBUTE_STR);
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
			if((attributes[ctr] = malloc(MAX_ATTRIBUTE_STR)) != NULL) {
				memset(attributes[ctr], 0, MAX_ATTRIBUTE_STR);
				strncpy(attributes[ctr], token, MAX_ATTRIBUTE_STR);
				token = strtok(NULL, ",");
				ctr++;
			}
		}

		if(ctr >= MAX_CIPHERTEXT_ATTRIBUTES) /* if we've reached max attributes */
			break;
	}
	
	attributes_len = ctr;
	/*for (i = 0; i < attributes_len; i++) {
		printf("Attribute '%i' = '%s'\n", i, attributes[i]);
	}*/
	return 0;
}

void generate_keys(char *outfile, FENC_SCHEME_TYPE scheme, char *secret_params, char *public_params)
{
	FENC_ERROR result;
	fenc_context context;
	fenc_group_params group_params;
	fenc_global_params global_params;
	fenc_function_input func_object_input; // could be policy or list
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
	uint8 output_str[SIZE];
	size_t output_str_len = 0;
	// size_t session_key_len;
	
	/* Clear data structures. */
	memset(&context, 0, sizeof(fenc_context));
	memset(&group_params, 0, sizeof(fenc_group_params));
	memset(&global_params, 0, sizeof(fenc_global_params));	
	memset(&public_params_buf, 0, SIZE);
	memset(&secret_params_buf, 0, SIZE);
	memset(output_str, 0, SIZE);
	/* stores user's authorized attributes */
	memset(&func_object_input, 0, sizeof(fenc_function_input));
	/* stores the user's private key */
	memset(&key, 0, sizeof(fenc_key)); 
	memset(&key2, 0, sizeof(fenc_key));

	/* Initialize the library. */
	result = libfenc_init();
	/* Create a Sahai-Waters context. */
	result = libfenc_create_context(&context, scheme);
			
	/* Load group parameters from a file. */
	fp = fopen(PARAM, "r");
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
		
	printf("Reading the public parameters file = %s\n", public_params);	
	/* read file */
	fp = fopen(public_params, "r");
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

	printf("Reading the secret parameters file = %s\n", secret_params);	
	/* read file */
	fp = fopen(secret_params, "r");
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
	
	if(scheme == FENC_SCHEME_LSW) {
		fenc_attribute_policy *parsed_policy = (fenc_attribute_policy *) malloc(sizeof(fenc_attribute_policy));
		if(parsed_policy == NULL) {
			printf("parsed_policy is NULL! Not good!");
		}
		memset(parsed_policy, 0, sizeof(fenc_attribute_policy)); 
		
		fenc_policy_from_string(parsed_policy, policy);
		int len = 1024;
		char pol_str[len];
		memset(pol_str, 0, len);
		fenc_attribute_policy_to_string(parsed_policy->root, pol_str, len);
		printf("Policy: %s\n", pol_str);
		
		func_object_input.input_type = FENC_INPUT_NM_ATTRIBUTE_POLICY;
		func_object_input.scheme_input = (void*)parsed_policy;
	}
	else if(scheme == FENC_SCHEME_WATERSCP || scheme == FENC_SCHEME_WATERSSIMPLECP) {
		// construct attributes list and place in the func_list_input object
		// char *attr[5] = {"ONE", "TWO", "THREE", "FOUR=100"};
		libfenc_create_attribute_list_from_strings(&func_object_input, attributes, attributes_len);
		// libfenc_create_attribute_list_from_strings(&func_list_input, attr, 4);
		fenc_attribute_list_to_buffer((fenc_attribute_list*)(func_object_input.scheme_input), output_str, SIZE, &output_str_len);
		printf("Attribute list: %s\n", output_str);
	}
		
	result = libfenc_extract_key(&context, &func_object_input, &key);
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
/*	
	if(scheme == FENC_SCHEME_LSW) {
		result = libfenc_import_secret_key(&context, &key2, buffer, serialized_len);
		report_error("Import secret key", result);
	
		fenc_key_LSW *myKey2 = (fenc_key_LSW *) key2.scheme_key;
	
		size_t serialized_len2;
		uint8 *buffer2 = malloc(KEYSIZE_MAX);
		memset(buffer2, 0, KEYSIZE_MAX);
		result = libfenc_serialize_key_LSW(myKey2, buffer2, KEYSIZE_MAX, &serialized_len2);		
		report_error("Serialize user's key", result);
	
		printf("Key-len2: '%zu'\n", serialized_len2);
		printf("Buffer contents 2:\n");
		print_buffer_as_hex(buffer2, serialized_len2);
	}*/
cleanup:
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
