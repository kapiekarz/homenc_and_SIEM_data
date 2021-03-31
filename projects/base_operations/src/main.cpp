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
    struct encrypt_parameters params;
    params.p = 4999;
    params.m = 32109;
    params.bits = 1000;

    // set NTL Thread pool size
    if (params.nthreads > 1)
        NTL::SetNumThreads(params.nthreads);

    helib::Context context(params.m, params.p, params.r);
    helib::buildModChain(context, params.bits, params.c);
    helib::SecKey secret_key = helib::SecKey(context);
    secret_key.GenSecKey();
    helib::addSome1DMatrices(secret_key);
    const helib::PubKey &public_key = secret_key;
    const helib::EncryptedArray &ea = *(context.ea);

    struct helib_context ctx = {&context, public_key, secret_key};

    std::cout << "Encrypting..." << std::endl;
    struct encrypted_data data = encrypt(ctx, "./data/short-test.csv");
    std::cout << "Adding..." << std::endl;
    helib::Ctxt result = add(ctx, params, data, 0, 1, "0");
    std::cout << "Decrypting..." << std::endl;
    std::string s_result = decrypt(ctx, result);

    std::cout << s_result << std::endl;
}