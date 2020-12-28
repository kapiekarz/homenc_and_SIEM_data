#include <iostream>

#include <helib/helib.h>
#include <helib/EncryptedArray.h>
#include <helib/ArgMap.h>
#include <NTL/BasicThreadPool.h>

#define IP_INFORMATION_INDEX 8
#define DATA_TO_SUM_INDEX 2
#define FILE_PATH "./short-test.csv"

// Utility function to read <K,V> CSV data from file
std::vector<std::vector<std::string>> read_csv(std::string filename)
{
    std::vector<std::vector<std::string>> dataset;
    std::ifstream data_file(filename);

    if (!data_file.is_open())
        throw std::runtime_error(
            "Error: This example failed trying to open the data file: " + filename +
            "\n           Please check this file exists and try again.");

    std::vector<std::string> row;
    std::string line, entry, temp;

    if (data_file.good())
    {
        // Read each line of file
        while (std::getline(data_file, line))
        {
            row.clear();
            std::stringstream ss(line);
            while (getline(ss, entry, ','))
            {
                row.push_back(entry);
            }
            // Add key value pairs to dataset
            dataset.push_back(row);
        }
    }

    data_file.close();
    return dataset;
}

int main(int argc, char *argv[])
{
    /************ HElib boiler plate ************/

    // Note: The parameters have been chosen to provide a somewhat
    // faster running time with a non-realistic security level.
    // Do Not use these parameters in real applications.

    // Plaintext prime modulus
    unsigned long p = 4999;
    // Cyclotomic polynomial - defines phi(m)
    unsigned long m = 32109;
    // Hensel lifting (default = 1)
    unsigned long r = 1;
    // Number of bits of the modulus chain
    unsigned long bits = 1000;
    // Number of columns of Key-Switching matrix (default = 2 or 3)
    unsigned long c = 2;
    // Size of NTL thread pool (default =1)
    unsigned long nthreads = 1;
    // input database file name
    std::string db_filename = FILE_PATH;
    // debug output (default no debug output)
    bool debug = false;

    helib::ArgMap amap;
    amap.arg("m", m, "Cyclotomic polynomial ring");
    amap.arg("p", p, "Plaintext prime modulus");
    amap.arg("r", r, "Hensel lifting");
    amap.arg("bits", bits, "# of bits in the modulus chain");
    amap.arg("c", c, "# fo columns of Key-Switching matrix");
    amap.arg("nthreads", nthreads, "Size of NTL thread pool");
    amap.arg("db_filename",
             db_filename,
             "Qualified name for the database filename");
    amap.toggle().arg("-debug", debug, "Toggle debug output", "");
    amap.parse(argc, argv);

    // set NTL Thread pool size
    if (nthreads > 1)
        NTL::SetNumThreads(nthreads);

    std::cout << "---Initialising HE Environment ... ";
    // Initialize context
    // This object will hold information about the algebra used for this scheme.
    std::cout << "\nInitializing the Context ... ";
    HELIB_NTIMER_START(timer_Context);
    helib::Context context(m, p, r);
    HELIB_NTIMER_STOP(timer_Context);

    // Modify the context, adding primes to the modulus chain
    // This defines the ciphertext space
    std::cout << "\nBuilding modulus chain ... ";
    HELIB_NTIMER_START(timer_CHAIN);
    helib::buildModChain(context, bits, c);
    HELIB_NTIMER_STOP(timer_CHAIN);

    // Secret key management
    std::cout << "\nCreating Secret Key ...";
    HELIB_NTIMER_START(timer_SecKey);
    // Create a secret key associated with the context
    helib::SecKey secret_key = helib::SecKey(context);
    // Generate the secret key
    secret_key.GenSecKey();
    HELIB_NTIMER_STOP(timer_SecKey);

    // Compute key-switching matrices that we need
    HELIB_NTIMER_START(timer_SKM);
    helib::addSome1DMatrices(secret_key);
    HELIB_NTIMER_STOP(timer_SKM);

    // Public key management
    // Set the secret key (upcast: FHESecKey is a subclass of FHEPubKey)
    std::cout << "\nCreating Public Key ...";
    HELIB_NTIMER_START(timer_PubKey);
    const helib::PubKey &public_key = secret_key;
    HELIB_NTIMER_STOP(timer_PubKey);

    // Get the EncryptedArray of the context
    const helib::EncryptedArray &ea = *(context.ea);

    // Print the context
    std::cout << std::endl;
    if (debug)
        context.zMStar.printout();

    // Print the security level
    // Note: This will be negligible to improve performance time.
    std::cout << "\n***Security Level: " << context.securityLevel() << std::endl;

    // Get the number of slot (phi(m))
    long nslots = ea.size();
    std::cout << "\nNumber of slots: " << nslots << std::endl;

    /************ Read in the database ************/
    std::vector<std::vector<std::string>> logs;
    try
    {
        logs = read_csv(db_filename);
    }
    catch (std::runtime_error &e)
    {
        std::cerr << "\n"
                  << e.what() << std::endl;
        exit(1);
    }

    // Convert strings into numerical vectors
    std::cout << "\n---Initializing the encrypted key,value pair logs ("
              << logs.size() << " lines)...";
    std::cout
        << "\nConverting strings to numeric representation into Ptxt objects ..."
        << std::endl;

    // Generating the Plain text representation of Country DB
    HELIB_NTIMER_START(timer_PtxtLOGS);
    std::vector<std::vector<helib::Ptxt<helib::BGV>>> logs_ptxt;
    for (const auto &log_line : logs)
    {
        std::vector<helib::Ptxt<helib::BGV>> logs_line_ptxt;
        for (const auto &log_item : log_line)
        { 
            helib::Ptxt<helib::BGV> item(context);
            for (long i = 0; i < log_item.size(); ++i){
                item.at(i) = log_item[i];
            }
            logs_line_ptxt.emplace_back(std::move(item));
        }
        logs_ptxt.emplace_back(logs_line_ptxt);
    }
    HELIB_NTIMER_STOP(timer_PtxtLOGS);

    // Encrypt the Country DB
    std::cout << "Encrypting the database..." << std::endl;
    HELIB_NTIMER_START(timer_CtxtLOGS);
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

    HELIB_NTIMER_STOP(timer_CtxtLOGS);

    // Print DB Creation Timers
    if (debug)
    {
        helib::printNamedTimer(std::cout << std::endl, "timer_Context");
        helib::printNamedTimer(std::cout, "timer_Chain");
        helib::printNamedTimer(std::cout, "timer_SecKey");
        helib::printNamedTimer(std::cout, "timer_SKM");
        helib::printNamedTimer(std::cout, "timer_PubKey");
        helib::printNamedTimer(std::cout, "timer_PtxtLOGS");
        helib::printNamedTimer(std::cout, "timer_CtxtLOGS");
    }

    std::cout << "\nInitialization Completed - Ready for Queries" << std::endl;
    std::cout << "--------------------------------------------" << std::endl;

    /** Create the query **/

    // Read in query from the command line
    std::string query_string;
    std::cout << "\nPlease enter ip: ";
    // std::cin >> query_string;
    std::getline(std::cin, query_string);
    std::cout << "Looking for the IP " << query_string << std::endl;
    std::cout << "This may take few minutes ... " << std::endl;

    HELIB_NTIMER_START(timer_TotalQuery);

    HELIB_NTIMER_START(timer_EncryptQuery);
    // Convert query to a numerical vector
    helib::Ptxt<helib::BGV> query_ptxt(context);
    for (long i = 0; i < query_string.size(); ++i)
        query_ptxt[i] = query_string[i];

    // Encrypt the query
    helib::Ctxt query(public_key);
    public_key.Encrypt(query, query_ptxt);
    HELIB_NTIMER_STOP(timer_EncryptQuery);

    /************ Perform the database search ************/

    HELIB_NTIMER_START(timer_QuerySearch);
    std::vector<std::vector<helib::Ctxt>> mask;
    mask.reserve(logs.size());
    for (const auto &encrypted_log_line : encrypted_logs)
    {
        std::vector<helib::Ctxt> mask_line;
        helib::Ctxt mask_entry = encrypted_log_line[IP_INFORMATION_INDEX]; // Copy of database key
        mask_entry -= query;                         // Calculate the difference
        mask_entry.power(p - 1);                     // Fermat's little theorem
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
     

    // Aggregate the results into a single ciphertext
    // Note: This code is for educational purposes and thus we try to refrain
    // from using the STL and do not use std::accumulate
    helib::Ctxt value = mask[0][0];
    for (int i = 1; i < mask.size(); i++)
        value += mask[i][DATA_TO_SUM_INDEX];

    HELIB_NTIMER_STOP(timer_QuerySearch);

    /************ Decrypt and print result ************/

    HELIB_NTIMER_START(timer_DecryptQueryResult);
    helib::Ptxt<helib::BGV> plaintext_result(context);
    secret_key.Decrypt(plaintext_result, value);
    HELIB_NTIMER_STOP(timer_DecryptQueryResult);

    // Convert from ASCII to a string
    std::string string_result;
    for (long i = 0; i < plaintext_result.size(); ++i)
        string_result.push_back(static_cast<long>(plaintext_result[i]));

    HELIB_NTIMER_STOP(timer_TotalQuery);

    // Print DB Query Timers
    if (debug)
    {
        helib::printNamedTimer(std::cout << std::endl, "timer_EncryptQuery");
        helib::printNamedTimer(std::cout, "timer_QuerySearch");
        helib::printNamedTimer(std::cout, "timer_DecryptQueryResult");
        std::cout << std::endl;
    }

    if (string_result.at(0) == 0x00)
    {
        string_result = "IP not in the database.";
    }
    std::cout << "\nQuery result: " << string_result << std::endl;
    helib::printNamedTimer(std::cout, "timer_TotalQuery");

    return 0;
}
