#include <iostream>

#include "../headers/helpers.h"

// Utility function to read CSV data from file
std::vector<std::vector<data_entry>> read_csv(std::string filename)
{
    std::vector<std::vector<int>> dataset;
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
            int i = 0;
            while (getline(ss, entry, ','))
            {
                data_entry cell;
                if(column_type[i] == 'i') {
                    cell.integrer_entry = std::stoi(entry);
                    call.type = 'i';
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
