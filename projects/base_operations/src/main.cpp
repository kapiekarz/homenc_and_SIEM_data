#include <iostream>
#include "../headers/helpers.h"
#include "../headers/encrypt.h"
#include "../headers/decrypt.h"
#include "../headers/methods.h"

int main(int argc, char *argv[])
{
    encrypt_parameters params;
    params.p = 4999;
    params.m = 32109;
    params.bits = 1000;
    
    encrypted_data data = encrypt(params, "../data/short-test.csv");
    encrypted_data result = add(data, 0, 1, "2");
    string result = decrypt(result);

    std::cout << result << std::endl;
}