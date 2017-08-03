#include <vector>
#include <array>
#include <iomanip>
#include <ict/ict.h>
#include <ict/command.h>

#include "sha256.h"


using std::cout;
using std::cerr;

using namespace ict::crypto;

int main(int argc, char ** argv) {
    try { 
        auto verbose = bool(false);
        auto use_file = bool(false);
        
        auto line = ict::command("sha256", "Compute the sha-256 hash of a string or file",
                "sha-256 [options] target...");
            line.add(ict::option{"verbose", 'V', "show progress", [&]{ verbose = true; }});
            line.add(ict::option{"file", 'f', "compute hash of file instead", [&]{ use_file = true; }});

        line.parse(argc, argv);

        if (line.targets.empty()) IT_THROW("no targets");

        for (auto & i : line.targets) {
            digest hash;
            if (use_file) {
                auto file = ict::read_file(i);
                hash = sha256(file.begin(), file.end());
            } else hash = sha256(i.begin(), i.end());
            cout << std::hex << hash << '\n';
        }
    }
    catch (std::exception & e) {
        cerr << e.what() << '\n';
        return 0;
    }
}
