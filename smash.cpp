#include <iostream>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include "signals.h"
#include "Commands.h"
#include <cstring>

bool checkChprompt (const char* line, std::string* promptPtr){
    char** args = new char*[COMMAND_MAX_ARGS];
    int numArgs = _parseCommandLine(line, args);
    if (numArgs == 0){
        delete[] args;
        return 1;
    }else if ((std::strcmp(args[0], "chprompt") == 0) && (numArgs == 1)){
        *promptPtr = "smash"; 
        for (int i = 0; i < numArgs; ++i) {
        free(args[i]); 
        }
        delete[] args;
        return 1;
    }else if ((std::strcmp(args[0], "chprompt") == 0)) {
        *promptPtr = args[1];
        for (int i = 0; i < numArgs; ++i) {
        free(args[i]); 
        }
        delete[] args;
        return 1;
    }
    for (int i = 0; i < numArgs; ++i) {
        free(args[i]); 
        }
        delete[] args;
    return 0;

}


int main(int argc, char *argv[]) {
    if (signal(SIGINT, ctrlCHandler) == SIG_ERR) {
        perror("smash error: failed to set ctrl-C handler");
    }
    std::string prompt = "smash"; 
    std::string *promptPtr = &prompt;
    SmallShell &smash = SmallShell::getInstance();
    while (true) {
        std::cout << prompt << "> ";
        std::string cmd_line;
        std::getline(std::cin, cmd_line);
    if(!checkChprompt( cmd_line.c_str(),promptPtr)){
        smash.executeCommand(cmd_line.c_str());
    }
    }
    return 0;
}