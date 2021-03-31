#include <iostream>
#include <helib/helib.h>
#include <helib/EncryptedArray.h>
#include <helib/ArgMap.h>
#include <NTL/BasicThreadPool.h>

#include "../headers/helpers.h"
#include "../headers/encrypt.h"

encrypted_data encrypt(encrypt_parameters params, filename)
{
    // set NTL Thread pool size
    if (params.nthreads > 1)
        NTL::SetNumThreads(params.nthreads);

    helib::Context context(params.m, params.p, params.r);
    helib::buildModChain(context, params.bits, params.c);
    helib::SecKey secret_key = helib::SecKey(context);
    helib::addSome1DMatrices(secret_key);
    const helib::PubKey &public_key = secret_key;
    const helib::EncryptedArray &ea = *(context.ea);

    std::vector<std::vector<data_entry>> logs;
    try
    {
        logs = read_csv(filename);
    }
    catch (std::runtime_error &e)
    {
        std::cerr << "\n"
                  << e.what() << std::endl;
        exit(1);
    }

    std::vector<std::vector<helib::Ptxt<helib::BGV>>> logs_ptxt;
    for (const auto &log_line : logs)
    {
        std::vector<helib::Ptxt<helib::BGV>> logs_line_ptxt;
        for (const auto &log_item : log_line)
        { 
            helib::Ptxt<helib::BGV> item(context);
            if(log_item.type == 'i') {
                item[0] = log_item.integrer_entry;
            } 
            if(log_item.type == 's') { 
                item[0] = log_item.text_entry;
            }
            logs_line_ptxt.emplace_back(std::move(item));
        }
        logs_ptxt.emplace_back(logs_line_ptxt);
    }

    std::vector<std::vector<helib::Ctxt>> encrypted_logs;
    for (const auto &log_line : logs_ptxt)
    {
        std::vector<helib::Ctxt> encrypted_log_line;
        for (const auto &log_item : log_line)
        {
            helib::Ctxt encrypted_log_item(public_key);
            public_key.Encrypt(encrypted_log_item, log_item);
            encrypted_log_line.emplace_back(std::move(encrypted_log_item));
        }
        
        encrypted_logs.emplace_back(encrypted_log_line);
    }

    encrypted_data ed;
    ed.data = encrypted_logs;
    ed.ctx = context;
    ed.pub_key = public_key;
    ed.sec_key = secret_key;

    return ed;
}