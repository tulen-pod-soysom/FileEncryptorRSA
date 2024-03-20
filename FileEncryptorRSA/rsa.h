#ifndef RSA_H
#define RSA_H

#include <random>
#include <string>

class RSA
{
public:
    RSA();

    std::random_device rd;
    std::mt19937 mt;

    struct PublicKey { unsigned int e,n;};
    struct PrivateKey{ unsigned int d,n;};

    struct Keys
    {
        PublicKey publicKey;
        PrivateKey privateKey;
    };


    unsigned long long ExpMOD( unsigned long long base,  unsigned long long exponent, unsigned long long mod);
    bool    IsPrime         (unsigned int number, unsigned int times = 10);
    int     GeneratePrime   ();
    int     GCD             (unsigned int a, unsigned int b);
    auto    ExtendedEuclid  (unsigned int a, unsigned int b);
    Keys    GenerateKeys    ();

    std::string Encrypt(std::string plainText    , PublicKey key);
    std::string Decrypt(std::string encryptedText, PrivateKey key);
};

#endif // RSA_H
