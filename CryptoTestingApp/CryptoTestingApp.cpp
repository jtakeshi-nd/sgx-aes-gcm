// CryptoTestingApp.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <cstdint>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <chrono>

using std::vector;
using std::cout;
using std::cerr;
using std::endl;
using std::istream;
using std::ifstream;
using std::cin;
using std::string;

#include "sgx_urts.h"
#include "CryptoEnclave_u.h"

#include "stdio.h"
#include "stdlib.h"
#include "string.h"

#define BUFLEN 2048
#define SGX_AESGCM_MAC_SIZE 16
#define SGX_AESGCM_IV_SIZE 12

#define ENCLAVE_FILE "CryptoEnclave.signed.so"

void emit_debug(const char *buf)

{
    printf("DEBUG: %s\n", buf);
}

int main()
{
	printf("Starting app...\n");
	
	/* Setup enclave */
	sgx_enclave_id_t eid;
	sgx_status_t ret;
	sgx_launch_token_t token = { 0 };
	int token_updated = 0;
	
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &token_updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("sgx_create_enclave failed: %#x\n", ret);
		getchar();
		return 1;
	}
	
	string infected_file = "";
  vector<string> user_files;
  
  int c;
  while((c = getopt(argc, argv, "i:f:")) != -1){
    switch(c){
      case 'i':{
        infected_file = optarg;
        break;
      }
      case 'f':{
        string tmp = optarg;
        user_files.push_back(tmp);
	      break;
      }		       
      default:{
        cout << "Unrecognized option: " << c << endl;
        return 0;
      }
    }
  }
  
  uint64_t tmp;
  ifstream i_ifs(infected_file);
  assert(i_ifs);
  vector<uint64_t> infected_vals;
  while(i_ifs >> tmp){
    infected_vals.push_back(tmp);
  }
	
	sgx_status_t enclave_result = send_set_to_enclave(global_eid, (unsigned char *) infected_vals.data(), infected_vals.size()*sizeof(uint64_t));
  if(enclave_result != SGX_SUCCESS){
    cerr << "ERROR: enclave failed!\n";
    print_error_message(enclave_result);
    return 1;
  }
  
  for(const string & fname : user_files){
    vector<uint64_t> vals;
    ifstream ifs(fname);
    if(!ifs){
      cout << "#WARNING: file " << fname << " could not be read" << endl;
      continue;
    }
    //Limit to only 2048/8 elements
    size_t num_vals = 0;
    while(ifs >> tmp && num_vals++ < BUFLEN/sizeof(uint64_t)){
      vals.push_back(tmp);
    }
    char * message = (char *) tmp.data();
    size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + (vals.size()*sizeof(uint64_t)));
    char *encMessage = (char *) malloc((encMessageLen+1)*sizeof(char));
    ret = encryptMessage(eid, message, (vals.size()*sizeof(uint64_t)), encMessage, encMessageLen);
	  encMessage[encMessageLen] = '\0';
	  std::chrono::high_resolution_clock::time_point start, end;
    start = std::chrono::high_resolution_clock::now();
    int empty;
	  ret = enclave_intersection_empty(global_eid, &empty, encMessage, encMessageLen, vals.size());
	  end = std::chrono::high_resolution_clock::now();
	  if(ret != SGX_SUCCESS){
      cerr << "ERROR: enclave failed in decryption/intersection!\n";
      return 1;
    }
    cout << "intersection_nonempty " << (double) std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count() << endl;
    //Free up ciphertext buffer
    free(encMessage);
    encMessage = NULL;
  }

  /*
	char *message = "Hello, crypto enclave!";
	printf("Original message: %s\n", message);

	// The encrypted message will contain the MAC, the IV, and the encrypted message itself.
	size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + strlen(message)); 
	char *encMessage = (char *) malloc((encMessageLen+1)*sizeof(char));

	printf("Encrypting...\n");
	ret = encryptMessage(eid, message, strlen(message), encMessage, encMessageLen);
	encMessage[encMessageLen] = '\0';
	printf("Encrypted message: %s\n", encMessage);
	
	// The decrypted message will contain the same message as the original one.
	size_t decMessageLen = strlen(message);
	char *decMessage = (char *) malloc((decMessageLen+1)*sizeof(char));

	printf("Decrypting...\n");
	ret = decryptMessage(eid,encMessage,encMessageLen,decMessage,decMessageLen);
	decMessage[decMessageLen] = '\0';
	printf("Decrypted message: %s", decMessage);
	*/

	/* Destroy the enclave */
  sgx_destroy_enclave(global_eid);
	return 0;
}

