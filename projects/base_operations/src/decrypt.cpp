#include <iostream>
#include <helib/helib.h>
#include <helib/EncryptedArray.h>
#include <helib/ArgMap.h>
#include <NTL/BasicThreadPool.h>

#include "../headers/helpers.h"
#include "../headers/decrypt.h"

std::string decrypt(struct encrypted_data enc_data, helib::Ctxt encrypted_result)
{
    std::cout << "\t" << "decrypting to plaintext" << std::endl;
    helib::Ptxt<helib::BGV> plaintext_result(enc_data.context);
    enc_data.sec_key.Decrypt(plaintext_result, encrypted_result);

    std::cout << "\t" << "converting to string" << std::endl;
    //Convert from ASCII to a string
    std::string string_result;
    for (long i = 0; i < plaintext_result.size(); ++i)
        string_result.push_back(static_cast<long>(plaintext_result[i]));

    return string_result;
}