#include <iostream>
#include <helib/helib.h>
#include <helib/EncryptedArray.h>
#include <helib/ArgMap.h>
#include <NTL/BasicThreadPool.h>

#include "../headers/helpers.h"
#include "../headers/methods.h"

struct encrypted_data add(struct encrypt_parameters params, struct encrypted_data enc_data, int add_column_no, int search_column_no, std::string query_string) {
    helib::Ptxt<helib::BGV> query_ptxt(*(enc_data.context));
    query_ptxt[0] = stoi(query_string);
    helib::Ctxt query(*(enc_data.pub_key));
    (*(enc_data.pub_key)).Encrypt(query, query_ptxt);
    const helib::EncryptedArray &ea = *((*(enc_data.context)).ea);

    std::vector<std::vector<helib::Ctxt>> mask;
    mask.reserve(*(enc_data.logs_size));
    for (const auto &encrypted_log_line : *(enc_data.data))
    {
        std::vector<helib::Ctxt> mask_line;
        helib::Ctxt mask_entry = encrypted_log_line[search_column_no]; // Copy of database key
        mask_entry -= query;                         // Calculate the difference
        mask_entry.power(params.p - 1);                     // Fermat's little theorem
        mask_entry.negate();                         // Negate the ciphertext
        mask_entry.addConstant(NTL::ZZX(1));         // 1 - mask = 0 or 1
        // Create a vector of copies of the mask
        std::vector<helib::Ctxt> rotated_masks(ea.size(), mask_entry);
        for (int i = 1; i < rotated_masks.size(); i++)
        ea.rotate(rotated_masks[i], i);             // Rotate each of the masks
        totalProduct(mask_entry, rotated_masks);      // Multiply each of the masks 
        for (const auto &encrypted_log_item : encrypted_log_line)
        {
            helib::Ctxt mask_entry2 = mask_entry; 
            mask_entry2.multiplyBy(encrypted_log_item); // multiply mask with values
            mask_line.push_back(mask_entry2);
        }
        mask.push_back(mask_line);
    }

    helib::Ctxt value = mask[0][add_column_no];
    for (int i = 1; i < mask.size(); i++) {
        value += mask[i][add_column_no];
    }

    struct encrypted_data ed = {
        enc_data.context,
        enc_data.pub_key,
        NULL,
        NULL,
        &value,
        NULL
    };

    return ed;
 }

 // struct encrypted_data search(struct encrypted_data enc_data, int search_column_no, std::string query_string) {}