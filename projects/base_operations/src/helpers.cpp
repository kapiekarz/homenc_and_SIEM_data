#include <iostream>

#include "../headers/helpers.h"
#include "../headers/decrypt.h"

// Utility function to read CSV data from file
std::vector<std::vector<struct data_entry>> read_csv(std::string filename)
{
    std::vector<std::vector<struct data_entry>> dataset;
    std::ifstream data_file(filename);

    if (!data_file.is_open())
        throw std::runtime_error(
            "Error: This example failed trying to open the data file: " + filename +
            "\n           Please check this file exists and try again.");

    std::vector<data_entry> row;
    std::string line, entry, temp;
    std::string column_type;
    std::getline(data_file, column_type);

    if (data_file.good())
    {   
        // Read each line of file
        while (std::getline(data_file, line))
        {
            row.clear();
            std::stringstream ss(line);
            int i = 3;
            while (getline(ss, entry, ';'))
            {
                struct data_entry cell;
                if(column_type[i] == 'i') {
                    if(entry.empty()){
                       cell.integrer_entry = 0;
                    } else {
                       cell.integrer_entry = std::stoi(entry);
                    }
                    cell.type = 'i';
                } 
                if(column_type[i] == 's') { 
                    cell.text_entry = entry;
                    cell.type = 's';
                }
                row.push_back(cell);
                i++;
            }
            // Add key value pairs to dataset
            dataset.push_back(row);
        }
    }

    data_file.close();
    return dataset;
}


void decrypt_and_print(std::string filename, struct helib_context ctx, std::vector<std::vector<helib::Ctxt>> result)
{
    std::ifstream data_file(filename);

    if (!data_file.is_open())
        throw std::runtime_error(
            "Error: This example failed trying to open the data file: " + filename +
            "\n           Please check this file exists and try again.");

    std::string column_type;
    std::getline(data_file, column_type);    
    
    for(const auto &row : result) {
        int j = 3;
        for(const auto &entry : row) {
            helib::Ptxt<helib::BGV>  decrypted_result = decrypt(ctx, entry);
            if(column_type[j] == 's'){
                std::string text;
                for (long i = 0; i < decrypted_result.size(); ++i) {
                    text.push_back(static_cast<long>(decrypted_result[i]));
                }
                std::cout << text << " "; 
            } else {
                std::cout << decrypted_result[0] << " ";
            }
            j++;
        }
        std::cout << std::endl;
    }
    

    data_file.close();
}
