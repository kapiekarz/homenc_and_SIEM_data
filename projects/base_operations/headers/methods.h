#include <iostream>
#include "helpers.h"

encrypted_data add(encrypted_data enc_data, int add_column_no, int search_column_no, std::string query_string);
encrypted_data search(encrypted_data enc_data, int search_column_no, std::string query_string);