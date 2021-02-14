#include "CryptoEnclave_t.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "stdlib.h"
#include <string.h>
#include <set>
#include <vector>
#include <cstdint>
#include <cassert>

using std::vector;
using std::set;

#define BUFLEN 16384
static sgx_aes_gcm_128bit_key_t key = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };

static set<uint64_t> infected_set;

void send_set_to_enclave(unsigned char * vals, size_t vals_bytes){
  size_t num_vals = vals_bytes / sizeof(uint64_t);
  if(vals_bytes % sizeof(uint64_t)){
    assert("Bytes calculation off" && 0);
    //printf("ERROR: bytes calculation off\n");
  }	 
  uint64_t * vals_ptr = (uint64_t *) vals;
  infected_set = set<uint64_t>(vals_ptr, vals_ptr + num_vals);
  return;
}

void decryptMessage(char *encMessageIn, size_t len, char *decMessageOut, size_t lenOut)
{
	uint8_t *encMessage = (uint8_t *) encMessageIn;
	uint8_t p_dst[BUFLEN] = {0};

	sgx_rijndael128GCM_decrypt(
		&key,
		encMessage + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		lenOut,
		p_dst,
		encMessage + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) encMessage);
	memcpy(decMessageOut, p_dst, lenOut);
}

int enclave_intersection_empty(char * encMessage, size_t encMessageLen, size_t num_64_vals){
  vector<uint64_t> data_vals(num_64_vals);
  decryptMessage(encMessage, encMessageLen, (char *) data_vals.data(), num_64_vals*sizeof(uint64_t));
  for(size_t i = 0; i < num_64_vals; i++){
    if(infected_set.find(data_vals[i]) != infected_set.end()){
      return 0;
    }
  }
  return 1;
}

void encryptMessage(char *decMessageIn, size_t len, char *encMessageOut, size_t lenOut)
{
	uint8_t *origMessage = (uint8_t *) decMessageIn;
	uint8_t p_dst[BUFLEN] = {0};

	// Generate the IV (nonce)
	sgx_read_rand(p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);

	sgx_rijndael128GCM_encrypt(
		&key,
		origMessage, len, 
		p_dst + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) (p_dst));	
	memcpy(encMessageOut,p_dst,lenOut);
}
