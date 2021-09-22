#ifndef FILT_H_
#define FILT_H_

#include <iostream>
#include <helib/helib.h>

enum filterfunction { NMATCH, MATCH };

std::vector<std::vector<helib::Ctxt>> notMatches(struct helib_context ctx,struct encrypt_parameters params,struct encrypted_data enc_data,int search_column_no,helib::Ctxt query);
std::vector<std::vector<helib::Ctxt>> matches(struct helib_context ctx,struct encrypt_parameters params,struct encrypted_data enc_data,int search_column_no,helib::Ctxt query);

#endif