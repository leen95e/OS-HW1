#include <iostream>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include "signals.h"
#include "Commands.cpp"
#include <cstring>

bool checkChprompt (const char* line, char* prompt){
    char** args = nullptr;
    int numArgs = _parseCommandLine(line, args);
    if (args == nullptr){
        return 1;
    }else if ((std::strcmp(args[0], "chprompt") == 0) && (numArgs == 1)){
        prompt = "smash> "; 
        return 1;
    }else if ((std::strcmp(args[0], "chprompt") == 0)) {
        prompt = args[1];
        return 1;
    }
    return 0;

}


int main(int argc, char *argv[]) {
    if (signal(SIGINT, ctrlCHandler) == SIG_ERR) {
        perror("smash error: failed to set ctrl-C handler");
    }

    char* prompt = "smash> "; 

    SmallShell &smash = SmallShell::getInstance();
    while (true) {
        std::cout << prompt;
        std::string cmd_line;
        std::getline(std::cin, cmd_line);
    if(!checkChprompt( cmd_line.c_str(),prompt)){
        smash.executeCommand(cmd_line.c_str());
    }
    }
    return 0;
}