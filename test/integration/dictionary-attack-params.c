#include <stdio.h>
#include "log.h"
#include "test.h"
#include "sapi/tpm20.h"
#include "sysapi_util.h"
/*
* This program contains SAPI integration test for Tss2_Sys_DictionaryAttackParameters.
* This is a use case scenario on setting up the dictionary attack parameters. 
* It sets up the parameters and verifies that the parameters were in fact setup 
* correctly by reading the variable capability structures using the tss command
* Tss2_Sys_GetCapability
*/
int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    //Command Auths
    TPMS_AUTH_COMMAND sessionData = { .sessionHandle = TPM_RS_PW,
            .nonce.t.size = 0, .hmac.t.size = 0, .sessionAttributes.val = 0 };
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    sessionDataArray[0] = &sessionData;
    TSS2_SYS_CMD_AUTHS sessionsData = { .cmdAuths = &sessionDataArray[0],
            .cmdAuthsCount = 1 };

    //Response Auths
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1], sessionDataOut;
    sessionDataOutArray[0] = &sessionDataOut;
    TSS2_SYS_RSP_AUTHS sessionsDataOut = { .rspAuths = &sessionDataOutArray[0],
            .rspAuthsCount = 1 };

    print_log("Setting up Dictionary Attack parameters.");
    UINT32 max_tries = 5;
    UINT32 recovery_time = 6;
    UINT32 lockout_recovery_time = 7;
    UINT32 rval = Tss2_Sys_DictionaryAttackParameters(sapi_context,
            TPM_RH_LOCKOUT, &sessionsData, max_tries,
            recovery_time, lockout_recovery_time,
            &sessionsDataOut);
    if (rval != TPM_RC_SUCCESS) {
        print_fail("Failed setting up dictionary_attack_lockout_reset params: 0x%x\n",
        	rval);
    }

    TPMI_YES_NO moreData;
 	TPMS_CAPABILITY_DATA capabilityData;
 	rval = Tss2_Sys_GetCapability( sapi_context, 0, TPM_CAP_TPM_PROPERTIES, 
 		TPM_PT_MAX_AUTH_FAIL, 1, &moreData, &capabilityData, 0 );
 	if (rval != TPM_RC_SUCCESS) {
 	    print_fail("Tss2_Sys_GetCapability failed: 0x%x", rval);
 	}
 	if (max_tries != capabilityData.data.tpmProperties.tpmProperty[0].value) {
 		print_fail("max_tries mismatched after setup.");
 	}

 	rval = Tss2_Sys_GetCapability( sapi_context, 0, TPM_CAP_TPM_PROPERTIES, 
 		TPM_PT_LOCKOUT_INTERVAL, 1, &moreData, &capabilityData, 0 );
 	if (rval != TPM_RC_SUCCESS) {
 	    print_fail("Tss2_Sys_GetCapability failed: 0x%x", rval);
 	}
 	if (recovery_time != capabilityData.data.tpmProperties.tpmProperty[0].value) {
 		print_fail("max_tries mismatched after setup.");
 	}

 	rval = Tss2_Sys_GetCapability( sapi_context, 0, TPM_CAP_TPM_PROPERTIES, 
 		TPM_PT_LOCKOUT_RECOVERY, 1, &moreData, &capabilityData, 0 );
 	if (rval != TPM_RC_SUCCESS) {
 	    print_fail("Tss2_Sys_GetCapability failed: 0x%x", rval);
 	}
 	if (lockout_recovery_time != capabilityData.data.tpmProperties.tpmProperty[0].value) {
 		print_fail("max_tries mismatched after setup.");
 	}
 	print_log("Tss2_Sys_DictionaryAttackParameters Test Passed.\n");       
}
