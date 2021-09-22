#include <iostream>
#include "helpers.h"
#include "filterfunctions.h"

helib::Ctxt add(struct helib_context ctx, struct encrypt_parameters params, struct encrypted_data enc_data, int add_column_no, int search_column_no, std::string query_string, bool verbose = false);
helib::Ctxt old_add(struct helib_context ctx, struct encrypt_parameters params, struct encrypted_data enc_data, int add_column_no, int search_column_no, std::string query_string, bool verbose = false);
helib::Ctxt search(struct helib_context ctx, struct encrypt_parameters params, struct encrypted_data enc_data, int search_column_no, std::string query_string, bool verbose = false);
helib::Ctxt average(struct helib_context ctx, struct encrypt_parameters params, struct encrypted_data enc_data, int avg_column_no, bool verbose);
std::vector<std::vector<helib::Ctxt>> filter(struct helib_context ctx, struct encrypt_parameters params, struct encrypted_data enc_data, int filter_column_no, std::string query_string, filterfunction function_name, bool verbose);