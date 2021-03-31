#include <iostream>
#include <helib/helib.h>

#include "../headers/helpers.h"
#include "../headers/decrypt.h"

std::string decrypt(struct helib_context ctx, helib::Ctxt encrypted_result)
{
    std::cout << "\t" << "decrypting to plaintext" << std::endl;
    helib::Ptxt<helib::BGV> plaintext_result(*(ctx.context));
    ctx.sec_key.Decrypt(plaintext_result, encrypted_result);

    std::cout << "\t" << plaintext_result << std::endl;

    std::cout << "\t" << "converting to string" << std::endl;
    //Convert from ASCII to a string
    std::string string_result;
    for (long i = 0; i < plaintext_result.size(); i++)
        string_result.push_back(static_cast<long>(plaintext_result[i]));
    
    std::cout << "\t" << string_result << std::endl;
    return string_result;
}