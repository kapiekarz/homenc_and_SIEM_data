#include <iostream>
#include <helib/helib.h>

#include "../headers/helpers.h"
#include "../headers/encrypt.h"

struct encrypted_data encrypt(struct helib_context ctx, std::string filename, bool verbose)
{
    if(verbose) std::cout << "\t" << "reading file" << std::endl;
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

    int logs_size = logs.size();

    if(verbose) std::cout << "\t" << "creating plaintext" << std::endl;
    std::vector<std::vector<helib::Ptxt<helib::BGV>>> logs_ptxt;
    for (const auto &log_line : logs)
    {
        std::vector<helib::Ptxt<helib::BGV>> logs_line_ptxt;
        for (const auto &log_item : log_line)
        { 
            helib::Ptxt<helib::BGV> item(*(ctx.context));
            if(log_item.type == 'i') {
                item[0] = log_item.integrer_entry;
            } 
            if(log_item.type == 's') { 
                for (long i = 0; i < log_item.text_entry.length(); ++i) {
                    item.at(i) = log_item.text_entry[i];
                }
            }
            logs_line_ptxt.emplace_back(std::move(item));
        }
        logs_ptxt.emplace_back(logs_line_ptxt);
    }

    if(verbose) std::cout << "\t" << "encrypting plaintext" << std::endl;
    std::vector<std::vector<helib::Ctxt>> encrypted_logs;
    for (const auto &log_line : logs_ptxt)
    {
        std::vector<helib::Ctxt> encrypted_log_line;
        for (const auto &log_item : log_line)
        {
            helib::Ctxt encrypted_log_item(ctx.pub_key);
            ctx.pub_key.Encrypt(encrypted_log_item, log_item);
            encrypted_log_line.emplace_back(std::move(encrypted_log_item));
        }
        encrypted_logs.emplace_back(encrypted_log_line);
    }

    struct encrypted_data data = {encrypted_logs, logs_size};

    return data;
}