#include <iostream>
#include <helib/helib.h>
#include <helib/EncryptedArray.h>
#include <NTL/BasicThreadPool.h>
#include "../headers/helpers.h"
#include "../headers/encrypt.h"
#include "../headers/decrypt.h"
#include "../headers/methods.h"

int main(int argc, char *argv[])
{
    long m_array[] = {helib::FindM(128, 1024, 3, 65537, 0, 0, 0), 18631, 21845, 28679, 35113, 42799, 45551, 49981, 51319, 65539};

    struct encrypt_parameters params;
    params.p = 65537;
    params.m = helib::FindM(128, 1024, 2, 65537, 1, 0, 0);
    params.bits = 1024;

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
    std::cout << context.securityLevel() << " ";

    struct helib_context ctx = {&context, public_key, secret_key};

    // std::cout << "Encrypting... ";
    struct encrypted_data data = encrypt(ctx, "./data/test-short.csv");

    // std::cout << "Adding... ";
    HELIB_NTIMER_START(timer_add);
    helib::Ctxt result2 = add(ctx, params, data, 0, 1, "0");
    HELIB_NTIMER_STOP(timer_add);
    // std::cout << "Decrypting... ";
    helib::Ptxt<helib::BGV>  decrypted_result2 = decrypt(ctx, result2);
    std::cout << decrypted_result2[0] << " "; 
    helib::printNamedTimer(std::cout, "timer_add");
    

    // std::cout << "Adding data form row 0 when row 1 is set to '0'..." << std::endl;
    // HELIB_NTIMER_START(timer_old_add);
    // helib::Ctxt result = old_add(ctx, params, data, 0, 1, "0");
    // HELIB_NTIMER_STOP(timer_old_add);
    // std::cout << "Decrypting..." << std::endl;
    // helib::Ptxt<helib::BGV>  decrypted_result = decrypt(ctx, result);
    // std::cout << decrypted_result[0] << std::endl;
    // helib::printNamedTimer(std::cout, "timer_old_add");

    // std::cout << "Searching all occurences when data in row 1 is '0'..." << std::endl;
    // HELIB_NTIMER_START(timer_search);
    // helib::Ctxt result3 = search(ctx, params, data, 1, "0");
    // HELIB_NTIMER_STOP(timer_search);
    // std::cout << "Decrypting..." << std::endl;
    // helib::Ptxt<helib::BGV>  decrypted_result3 = decrypt(ctx, result3);
    // std::cout << "Occurences: " << decrypted_result3[0] << std::endl;
    // helib::printNamedTimer(std::cout, "timer_search");
}