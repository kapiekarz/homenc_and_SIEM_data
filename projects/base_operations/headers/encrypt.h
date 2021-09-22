#include <iostream>
#include "helpers.h"

struct encrypted_data encrypt(struct helib_context ctx, std::string filename, bool verbose = false);