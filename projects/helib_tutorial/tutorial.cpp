#include <helib/helib.h>
#include <helib/EncryptedArray.h>
#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <sys/time.h>

int mulEntireArray(Ctxt &res, const vector<Ctxt> input, const EncryptedArray &ea)
{
    const int nrElem = input.size();
    if (nrElem > 0)
    {
        res = input[0];
        for (int i = 1; i < nrElem; i++)
        {
            res.multiplyBy(input[i]);
        }
        return 0;
    }
    return (-1);
}

int mulEntireArray_logNoise(Ctxt &res, const vector<Ctxt> input, const EncryptedArray &ea)
{
    const size_t nrElem = input.size();
    if (nrElem > 1)
    {
        vector<Ctxt> tmp((nrElem + 1) / 2, Ctxt(input[0].getPubKey()));
        const size_t sz = tmp.size();
        for (int i = 0; i < sz; i++)
        {
            tmp[i] = input[i];
        }
        for (int i = 0; i < sz && (sz + i) < nrElem; i++)
        {
            tmp[i].multiplyBy(input[sz + i]);
        }
        mulEntireArray_logNoise(res, tmp, ea);
    }
    else
        res = input[0];
    return 0;
}

int main(int argc, char **argv)
{
    /* On our trusted system we generate a new key
        * (or read one in) and encrypt the secret data set.
        */

    long m = 0, p = 2, r = 1; // Native plaintext space
                              // Computations will be 'modulo p'
    long L = 16;              // Levels
    long c = 3;               // Columns in key switching matrix
    long w = 64;              // Hamming weight of secret key
    long d = 0;
    long security = 128;
    ZZX G;
    m = FindM(security, L, c, p, d, 0, 0);

    FHEcontext context(m, p, r);
    // initialize context
    buildModChain(context, L, c);
    // modify the context, adding primes to the modulus chain
    FHESecKey secretKey(context);
    // construct a secret key structure
    const FHEPubKey &publicKey = secretKey;
    // an "upcast": FHESecKey is a subclass of FHEPubKey

    //if(0 == d)
    G = context.alMod.getFactorsOverZZ()[0];

    secretKey.GenSecKey(w);
    // actually generate a secret key with Hamming weight w

    addSome1DMatrices(secretKey);
    cout << "Generated key" << endl;

    EncryptedArray ea(context, G);
    // constuct an Encrypted array object ea that is
    // associated with the given context and the polynomial G

    long nslots = ea.size();

    vector<long> v1;
    for (int i = 0; i < nslots; i++)
    {
        v1.push_back(i * 2);
    }
    Ctxt ct1(publicKey);
    ea.encrypt(ct1, publicKey, v1);

    vector<long> v2;
    Ctxt ct2(publicKey);
    for (int i = 0; i < nslots; i++)
    {
        v2.push_back(i * 3);
    }
    ea.encrypt(ct2, publicKey, v2);

    // On the public (untrusted) system we
    // can now perform our computation

    Ctxt ctSum = ct1;
    Ctxt ctProd = ct1;

    ctSum += ct2;
    ctProd *= ct2;

    vector<long> res;
    ea.decrypt(ctSum, secretKey, res);

    cout << "All computations are modulo " << p << "." << endl;
    for (int i = 0; i < res.size(); i++)
    {
        cout << v1[i] << " + " << v2[i] << " = " << res[i] << endl;
    }

    ea.decrypt(ctProd, secretKey, res);
    for (int i = 0; i < res.size(); i++)
    {
        cout << v1[i] << " * " << v2[i] << " = " << res[i] << endl;
    }

    return 0;
}