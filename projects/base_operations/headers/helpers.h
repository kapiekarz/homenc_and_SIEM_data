#ifndef HELPERS_H_
#define HELPERS_H_

#include <iostream>
#include <helib/helib.h>

#include "decrypt.h"

struct data_entry {
    int integrer_entry;
    std::string text_entry;
    char type;
};

struct encrypt_parameters {
    encrypt_parameters() : r(1), c(2), nthreads(1) {}
    // Plaintext prime modulus
    unsigned long p;
    // Cyclotomic polynomial - defines phi(m)
    unsigned long m;
    // Number of bits of the modulus chain
    unsigned long bits;
    // Hensel lifting (default = 1)
    unsigned long r;
    // Number of columns of Key-Switching matrix (default = 2 or 3)
    unsigned long c;
    // Size of NTL thread pool (default = 1)
    unsigned long nthreads;
};

struct helib_context {
    helib::Context* context;
    const helib::PubKey pub_key;
    const helib::SecKey sec_key;
};

struct encrypted_data {
    std::vector<std::vector<helib::Ctxt>> data;
    int logs_size;
};

// Utility function to read CSV data from file
std::vector<std::vector<data_entry>> read_csv(std::string filename);
void decrypt_and_print(std::string filename, struct helib_context ctx, std::vector<std::vector<helib::Ctxt>> result);

#endif