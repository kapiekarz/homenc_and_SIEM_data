#include <iostream>
#include <helib/helib.h>

#include "../headers/helpers.h"
#include "../headers/decrypt.h"

helib::Ptxt<helib::BGV>  decrypt(struct helib_context ctx, helib::Ctxt encrypted_result)
{
    std::cout << "\t" << "decrypting to plaintext" << std::endl;
    helib::Ptxt<helib::BGV> plaintext_result(*(ctx.context));
    ctx.sec_key.Decrypt(plaintext_result, encrypted_result);

    return plaintext_result;
}