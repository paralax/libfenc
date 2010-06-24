#include <ctype.h>
#include "common.h"

#define MAX_STR 4096

/* tool to test policy parsing */
int main(int argc, char *argv[]) {
	
	/* make sure we only have one argument */
	if(argc != 2) {
		printf("Usage: %s [ policy-string ]\n", argv[0]);
		exit(1);
	}

	FENC_ERROR result;
	char *policy = argv[1];
	char policy_str[MAX_STR];
	size_t policy_str_len = MAX_STR;
	/* allocate policy structure */
	fenc_attribute_policy *parsed_policy = (fenc_attribute_policy *) malloc(sizeof(fenc_attribute_policy));
	if(parsed_policy == NULL) {
		printf("parsed_policy is NULL!");
	}
	memset(parsed_policy, 0, sizeof(fenc_attribute_policy)); 
	
	/* convert policy string into policy structure */
	fenc_policy_from_string(parsed_policy, policy);

	/* serialize policy struct to buffer */	
	memset(policy_str, 0, MAX_STR);
	result = fenc_attribute_policy_to_string(parsed_policy->root, policy_str, policy_str_len);

	/* see if they are equivalent? */
	printf("Output:\t'%s'\n", policy_str);
	printf("Strlen: %d\n", strlen(policy_str));

	//char *test = parse_policy_lang_as_str(policy_str);
	//printf("\nOriginal? '%s'\n", test);

	return 0;
}

