#include <stdio.h>
#include "log.h"
#include "test.h"
#include "sapi/tpm20.h"
#include "sysapi_util.h"
/*
* This program contains integration test for SAPI Tss2_sys_dictionary_lockout.
* This is a use case scenario on setting up the dictionary lockout parameters. 
* It sets up the parameters and verifies that the parameters were in fact setup 
* correctly by reading the variable capability structures using the tss command
* Tss2_Sys_GetCapability
*/
int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
	
}
