#include <iostream>
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
    
    std::cout << "Encrypting..." << std::endl;
    encrypted_data data = encrypt(params, "../data/short-test.csv");
    std::cout << "Adding..." << std::endl;
    encrypted_data result = add(params, data, 0, 1, "2");
    std::cout << "Decrypting..." << std::endl;
    std::string s_result = decrypt(result);

    std::cout << s_result << std::endl;
}