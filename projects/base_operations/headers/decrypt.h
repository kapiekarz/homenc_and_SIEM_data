#ifndef DECR_H_
#define DECR_H_

#include <iostream>
#include "helpers.h"

helib::Ptxt<helib::BGV> decrypt(struct helib_context ctx, helib::Ctxt encrypted_result, bool verbose = false);

#endif