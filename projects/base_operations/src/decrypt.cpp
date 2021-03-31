#include <iostream>
#include <helib/helib.h>
#include <helib/EncryptedArray.h>
#include <helib/ArgMap.h>
#include <NTL/BasicThreadPool.h>

#include "../headers/helpers.h"
#include "../headers/decrypt.h"

string decrypt(encrypted_data enc_data)
{
    helib::Ptxt<helib::BGV> plaintext_result(enc_data.context);
    enc_data.sec_key.Decrypt(plaintext_result, ed.data);

    return plaintext_result;
}