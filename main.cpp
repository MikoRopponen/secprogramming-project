#include <iostream>
#include <string>
extern "C"{
#include <multitool_evp.h>
}
int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        std::cout << "Command line params req: [encrypt/decrypt] [Filepath]" << std::endl;

    }
    std::string modeString;
    int mode;

    modeString = argv[1];

    if(modeString == "encrypt"){
        mode = 1;
    }
    else if (modeString == "decrypt")
    {
        mode = 0;
    }
    else
    {
        std::cout << modeString + " is not a valid mode, please type either encrypt/decrypt" << std::endl;
        return 0;
    }

    if(!crypt_evp(mode, argv[2]))
    {
        std::cout << "\nOperation failed" << std::endl;

    }
    else
    {
        std::cout << "Operation Successful" << std::endl;
    }

    return 0;
}
