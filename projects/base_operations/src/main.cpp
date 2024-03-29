#include <iostream>
#include <helib/helib.h>
#include <helib/EncryptedArray.h>
#include <NTL/BasicThreadPool.h>
#include "../headers/helpers.h"
#include "../headers/encrypt.h"
#include "../headers/decrypt.h"
#include "../headers/methods.h"
#include "../headers/filterfunctions.h"

int main(int argc, char *argv[])
{
    struct encrypt_parameters params;
    params.p = 2131; 
    params.c = 3;
    params.nthreads = 8;
    params.m = helib::FindM(64, 1000, params.c, params.p, 1, 0, 0);
    params.bits = 1000;

    std::cout <<  params.m << std::endl;

    // set NTL Thread pool size
    if (params.nthreads > 1)
        NTL::SetNumThreads(params.nthreads);

    helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(params.m)
                               .p(params.p)
                               .r(params.r)
                               .bits(params.bits)
                               .c(params.c)
                               .build();
    
    helib::SecKey secret_key = helib::SecKey(context);
    secret_key.GenSecKey();
    helib::addSome1DMatrices(secret_key);
    const helib::PubKey &public_key = secret_key;
    const helib::EncryptedArray &ea = context.getEA();
    std::cout << context.securityLevel() << std::endl;

    struct helib_context ctx = {&context, public_key, secret_key};

    std::cout << "Encrypting... ";
    HELIB_NTIMER_START(timer_enc);
    struct encrypted_data data = encrypt(ctx, "./data/investigation-short3.csv", true);
    HELIB_NTIMER_STOP(timer_enc);
    helib::printNamedTimer(std::cout, "timer_enc");

    // std::cout << "Adding... ";
    // HELIB_NTIMER_START(timer_add2);
    // std::cout << "adding all entries in column 2, when the column 3 has value '37'" << std::endl;
    // helib::Ctxt result2 = old_add(ctx, params, data, 2, 3, "37", true);
    // HELIB_NTIMER_STOP(timer_add2);
    // std::cout << "Decrypting... ";
    // HELIB_NTIMER_START(timer_dec2);
    // helib::Ptxt<helib::BGV>  decrypted_result2 = decrypt(ctx, result2, true);
    // HELIB_NTIMER_STOP(timer_dec2);
    // std::cout << decrypted_result2[0] << " "; 
    // helib::printNamedTimer(std::cout, "timer_add2");
    // helib::printNamedTimer(std::cout, "timer_dec2");

    // std::cout << "Adding... ";
    // HELIB_NTIMER_START(timer_add);
    // std::cout << "adding all entries in column 2, when the column 3 has value '37'" << std::endl;
    // helib::Ctxt result2 = add(ctx, params, data, 2, 3, "37", true);
    // HELIB_NTIMER_STOP(timer_add);
    // std::cout << "Decrypting... ";
    // HELIB_NTIMER_START(timer_dec);
    // helib::Ptxt<helib::BGV>  decrypted_result2 = decrypt(ctx, result2, true);
    // HELIB_NTIMER_STOP(timer_dec);
    // std::cout << decrypted_result2[0] << " "; 
    // helib::printNamedTimer(std::cout, "timer_add");
    // helib::printNamedTimer(std::cout, "timer_dec");


    // std::cout << "Searching all occurences when data in column 3 is '37'..." << std::endl;
    // HELIB_NTIMER_START(timer_search);
    // helib::Ctxt result3 = search(ctx, params, data, 3, "37", true);
    // HELIB_NTIMER_STOP(timer_search);
    // std::cout << "Decrypting..." << std::endl;
    // HELIB_NTIMER_START(timer_dec3);
    // helib::Ptxt<helib::BGV>  decrypted_result3 = decrypt(ctx, result3);
    //  HELIB_NTIMER_STOP(timer_dec3);
    // std::cout << "Occurences: " << decrypted_result3[0] << std::endl;
    // helib::printNamedTimer(std::cout, "timer_search");
    // helib::printNamedTimer(std::cout, "timer_dec3");

    // std::cout << "Calculating average... ";
    // HELIB_NTIMER_START(timer_avg);
    // std::cout << "Average of all entries in column 2" << std::endl;
    // helib::Ctxt result4 = average(ctx, params, data, 2, true);
    // HELIB_NTIMER_STOP(timer_avg);
    // std::cout << "Decrypting... ";
    // HELIB_NTIMER_START(timer_dec3);
    // helib::Ptxt<helib::BGV>  decrypted_result4 = decrypt(ctx, result4, true);
    // HELIB_NTIMER_STOP(timer_dec3);
    // std::cout << decrypted_result4[0] << " "; 
    // helib::printNamedTimer(std::cout, "timer_avg");
    // helib::printNamedTimer(std::cout, "timer_dec3");

    std::cout << "Filtering... ";
    HELIB_NTIMER_START(timer_filt1);
    std::cout << "Filtering all records that have '76' in column 2" << std::endl;
    std::vector<std::vector<helib::Ctxt>> result5 = filter(ctx, params, data, 2, "76", MATCH, true);
    HELIB_NTIMER_STOP(timer_filt1);
    std::cout << "Decrypting... " << std::endl;
    HELIB_NTIMER_START(timer_dec4);
    decrypt_and_print("./data/investigation-short3.csv", ctx, result5);
    HELIB_NTIMER_STOP(timer_dec4);
    helib::printNamedTimer(std::cout, "timer_filt1");
    helib::printNamedTimer(std::cout, "timer_dec4");

    // std::cout << "Filtering... ";
    // HELIB_NTIMER_START(timer_filt2);
    // std::cout << "Filtering all records that don't have '76' in column 2" << std::endl;
    // std::vector<std::vector<helib::Ctxt>> result6 = filter(ctx, params, data, 2, "76", NMATCH, true);
    // HELIB_NTIMER_STOP(timer_filt2);
    // std::cout << "Decrypting... " << std::endl;
    // HELIB_NTIMER_START(timer_dec5);
    // decrypt_and_print("./data/investigation-short3.csv", ctx, result6);
    // HELIB_NTIMER_STOP(timer_dec5);
    // helib::printNamedTimer(std::cout, "timer_filt2");
    // helib::printNamedTimer(std::cout, "timer_dec5");
}