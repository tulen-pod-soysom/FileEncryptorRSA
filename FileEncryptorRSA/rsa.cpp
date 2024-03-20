#include "rsa.h"

RSA::RSA()
{
    mt.seed(rd());
}

unsigned long long RSA::ExpMOD( unsigned long long base,  unsigned long long exponent, unsigned long long mod)
{
     unsigned long long a = 1;
     unsigned long long b = base;
    while (exponent > 0)
    {
        if (exponent % 2 == 1)
        a = (a * b) % mod;
        b = (b * b);
        b = b % mod;
        exponent = exponent / 2;
    }
    return a % mod;
}

bool RSA::IsPrime(unsigned int number, unsigned int times)
{
    auto& n = number; if (n < 4) return 1;

        std::uniform_int_distribution<> dist(2,n-2);
        int a;

        for (int i = 0; i < times; i++)
        {
            a = dist(mt);

            if (ExpMOD(a, n - 1, n) != 1) return false;
        }
        return true;
}

int RSA::GeneratePrime()
{
    int a;
    do
    {
        a = std::uniform_int_distribution<>(256,65536)(mt);
    }  while (!IsPrime(a));
    return a;
}

int RSA::GCD(unsigned int a, unsigned int b)
{
    //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    unsigned int r;
    while (true)
    {
        r = a % b;
        if (r == 0) return b;
        a = b; b = r;
    }
    //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
}


auto RSA::ExtendedEuclid(unsigned int a, unsigned int b)
{
    std::vector<unsigned int> r{a,b};
    std::vector<long> s{1,0};
    std::vector<long> t{0,1};

    while (r[1] != 0) {
        int q = r[0] / r[1];
        r = {r[1],r[0] - q* r[1]};
        s = {s[1],s[0] - q* s[1]};
        t = {t[1],t[0] - q* t[1]};
    }

    struct EuclidOut
    {
        std::vector<int> bezu;
        unsigned int gcd;
    } out;

    out.bezu = {s[0],t[0]};
    out.gcd = r[0];

    return out;
}

RSA::Keys RSA::GenerateKeys()
{
    int p,q;
    p = GeneratePrime();
    q = GeneratePrime();

    unsigned int n = p*q;
    unsigned int phi = (p-1)*(q-1);

    unsigned int e = 0;

    do {
        e = std::uniform_int_distribution<unsigned int>(1,phi)(mt);
    } while (GCD(e,phi) != 1);
//    e = 3;

    unsigned int d = ExtendedEuclid(e,phi).bezu[0];


    Keys keys;
    keys.publicKey =    {e,n};
    keys.privateKey =   {d,n};

    return keys;
}

std::string RSA::Encrypt(std::string plainText,PublicKey key)
{
    std::string encryptedText(2*plainText.size(),' ');
    auto& e = key.e;
    auto& n = key.n;

    wchar_t a = 0;
    auto pt = reinterpret_cast<char*>(&a);
    for (int var = 0; var < plainText.size()/sizeof(a); ++var) {
        *(pt+0) = plainText[var*2 + 0];
        *(pt+1) = plainText[var*2 + 1];
        unsigned int exp = ExpMOD(a,e,n); auto pt_ = reinterpret_cast<char*>(&exp);
        encryptedText[4*var+0] = *(pt_+0);
        encryptedText[4*var+1] = *(pt_+1);
        encryptedText[4*var+2] = *(pt_+2);
        encryptedText[4*var+3] = *(pt_+3);
    }
    return encryptedText;
}

std::string RSA::Decrypt(std::string encryptedText,PrivateKey key)
{
    std::string plainText(encryptedText.size()/2,' ');
    auto& d = key.d;
    auto& n = key.n;

    unsigned int a = 0;
    auto pt = reinterpret_cast<char*>(&a);
    for (int var = 0; var < encryptedText.size()/4; ++var) {
        *(pt+0) = encryptedText[var*4 + 0];
        *(pt+1) = encryptedText[var*4 + 1];
        *(pt+2) = encryptedText[var*4 + 2];
        *(pt+3) = encryptedText[var*4 + 3];
        unsigned int exp = ExpMOD(a,d,n); auto pt_ = reinterpret_cast<char*>(&exp);
        plainText[var*2+0] = *(pt_+0);
        plainText[var*2+1] = *(pt_+1);
    }

    return plainText;
}



