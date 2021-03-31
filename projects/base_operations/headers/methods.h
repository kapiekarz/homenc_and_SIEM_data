#include <iostream>
#include "helpers.h"

struct encrypted_data add(struct encrypt_parameters params, struct encrypted_data enc_data, int add_column_no, int search_column_no, std::string query_string);
// struct encrypted_data search(struct encrypted_data enc_data, int search_column_no, std::string query_string);