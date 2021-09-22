#include <iostream>
#include <helib/helib.h>
#include <helib/EncryptedArray.h>

#include "../headers/helpers.h"
#include "../headers/filterfunctions.h"

std::vector<std::vector<helib::Ctxt>> contains(struct helib_context ctx,struct encrypt_parameters params,struct encrypted_data enc_data,int search_column_no,helib::Ctxt query) {
    const helib::EncryptedArray &ea = (*(ctx.context)).getEA();
    std::vector<std::vector<helib::Ctxt>> mask;
    mask.reserve(enc_data.logs_size);

    for (const auto &encrypted_log_line : enc_data.data)
    {
        std::vector<helib::Ctxt> mask_line;
        helib::Ctxt mask_entry = encrypted_log_line[search_column_no]; // Copy of database key
        mask_entry -= query;                         // Calculate the difference
        mask_entry.power(params.p - 1);              // Fermat's little theorem
        mask_entry.negate();                         // Negate the ciphertext
        mask_entry.addConstant(NTL::ZZX(1));         // 1 - mask = 0 or 1

        helib::Ctxt mask_entry_unified = mask_entry;
        totalSums(mask_entry_unified);
        mask_entry_unified.addConstant(NTL::ZZX(-ea.size()));
        mask_entry_unified.power(params.p - 1);         
        mask_entry_unified.negate();                          
        mask_entry_unified.addConstant(NTL::ZZX(1));    

        std::vector<helib::Ctxt> mask_entry_unified_vector = {mask_entry_unified};

        totalProduct(mask_entry, mask_entry_unified_vector);   
        for (const auto &encrypted_log_item : encrypted_log_line)
        {
            helib::Ctxt mask_entry2 = mask_entry; 
            mask_entry2.multiplyBy(encrypted_log_item); // multiply mask with values
            mask_line.push_back(mask_entry2);
        }
        mask.push_back(mask_line);
    }
    return mask;
}

std::vector<std::vector<helib::Ctxt>> matches(struct helib_context ctx,struct encrypt_parameters params,struct encrypted_data enc_data,int search_column_no,helib::Ctxt query) {
    const helib::EncryptedArray &ea = (*(ctx.context)).getEA();
    std::vector<std::vector<helib::Ctxt>> mask;
    mask.reserve(enc_data.logs_size);

    for (const auto &encrypted_log_line : enc_data.data)
    {
        std::vector<helib::Ctxt> mask_line;
        helib::Ctxt mask_entry = encrypted_log_line[search_column_no]; // Copy of database key
        mask_entry -= query;                         // Calculate the difference
        mask_entry.power(params.p - 1);              // Fermat's little theorem
        mask_entry.negate();                         // Negate the ciphertext
        mask_entry.addConstant(NTL::ZZX(1));         // 1 - mask = 0 or 1

        helib::Ctxt mask_entry_unified = mask_entry;
        totalSums(mask_entry_unified);
        mask_entry_unified.addConstant(NTL::ZZX(-ea.size()));
        mask_entry_unified.power(params.p - 1);         
        mask_entry_unified.negate();                          
        mask_entry_unified.addConstant(NTL::ZZX(1));    

        std::vector<helib::Ctxt> mask_entry_unified_vector = {mask_entry_unified};

        totalProduct(mask_entry, mask_entry_unified_vector);   
        for (const auto &encrypted_log_item : encrypted_log_line)
        {
            helib::Ctxt mask_entry2 = mask_entry; 
            mask_entry2.multiplyBy(encrypted_log_item); // multiply mask with values
            mask_line.push_back(mask_entry2);
        }
        mask.push_back(mask_line);
    }
    return mask;
}
