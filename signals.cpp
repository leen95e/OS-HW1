#include <iostream>
#include <signal.h>
#include "signals.h"
#include "Commands.h"

using namespace std;

void ctrlCHandler(int sig_num) {
    std::cout << "smash: got ctrl-C" << std::endl;
    SmallShell& smash = SmallShell::getInstance();
    pid_t fpid = smash.getForegroundPid(); 

    if (fpid != -1) {
        if (kill(fpid, SIGKILL) == -1) {
            perror("smash error: kill failed");
        } else {
            std::cout << "smash: process " << fpid << " was killed" << std::endl;
        }
    }
    // If fpid is -1, there is no foreground process, and the signal is ignored.}
}