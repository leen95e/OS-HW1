#include <unistd.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <sys/wait.h>
#include <iomanip>
#include "Commands.h"


#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <stdexcept>

#include <limits.h>
#include <cstring>


using namespace std;

const std::string WHITESPACE = " \n\r\t\f\v";

#if 0
#define FUNC_ENTRY()  \
  cout << __PRETTY_FUNCTION__ << " --> " << endl;

#define FUNC_EXIT()  \
  cout << __PRETTY_FUNCTION__ << " <-- " << endl;
#else
#define FUNC_ENTRY()
#define FUNC_EXIT()
#endif

string _ltrim(const std::string &s) {
    size_t start = s.find_first_not_of(WHITESPACE);
    return (start == std::string::npos) ? "" : s.substr(start);
}

string _rtrim(const std::string &s) {
    size_t end = s.find_last_not_of(WHITESPACE);
    return (end == std::string::npos) ? "" : s.substr(0, end + 1);
}

string _trim(const std::string &s) {
    return _rtrim(_ltrim(s));
}

int _parseCommandLine(const char *cmd_line, char **args) {
    FUNC_ENTRY()
    int i = 0;
    std::istringstream iss(_trim(string(cmd_line)).c_str());
    for (std::string s; iss >> s;) {
        args[i] = (char *) malloc(s.length() + 1);
        memset(args[i], 0, s.length() + 1);
        strcpy(args[i], s.c_str());
        args[++i] = NULL;
    }
    return i;
    FUNC_EXIT()
}

bool _isBackgroundComamnd(const char *cmd_line) {
    const string str(cmd_line);
    return str[str.find_last_not_of(WHITESPACE)] == '&';
}

void _removeBackgroundSign(char *cmd_line) {
    const string str(cmd_line);
    // find last character other than spaces
    unsigned int idx = str.find_last_not_of(WHITESPACE);
    // if all characters are spaces then return
    if (idx == string::npos) {
        return;
    }
    // if the command line does not end with & then return
    if (cmd_line[idx] != '&') {
        return;
    }
    // replace the & (background sign) with space and then remove all tailing spaces.
    cmd_line[idx] = ' ';
    // truncate the command line string up to the last non-space character
    cmd_line[str.find_last_not_of(WHITESPACE, idx) + 1] = 0;
}


//converts string to int 

bool get_positive_integer_value_legacy(const std::string& str, int* outValue) {
    if (str.empty() || str[0] == '-' || str[0] == '+') {
        return false; // Fail
    }
    
    try {
        size_t last_char_idx;
        int value = std::stoi(str, &last_char_idx);
        // 1. Check if the entire string was consumed
        if (last_char_idx != str.length()) {
            return false;
        }
        // 2. Check if the value is strictly positive (> 0)
        if (value > 0) {
            *outValue = value; // Set the output parameter
            return true;       // Success
        } else {
            return false; // Fail: Value is zero
        }

    } catch (const std::exception& e) {
        return false; // Fail: Overflow or invalid format
    }
}




// TODO: Add your implementation for classes in Commands.h 

SmallShell::SmallShell()  : plastPwd(nullptr), jobs(nullptr) {}

SmallShell::~SmallShell() {
    // TODO: add your implementation
}

/**
* Creates and returns a pointer to Command class which matches the given command line (cmd_line)
*/
Command *SmallShell::CreateCommand(const char *cmd_line) {
    
    string cmd_s = _trim(string(cmd_line));
    string firstWord = cmd_s.substr(0, cmd_s.find_first_of(" \n"));

    if (firstWord.compare("pwd") == 0) {
      return new GetCurrDirCommand(cmd_line);
    }
    else if (firstWord.compare("showpid") == 0) {
      return new ShowPidCommand(cmd_line);
    }
    else if (firstWord.compare("jobs") == 0){
        return new JobsCommand(cmd_line,jobs);
    }
    else if (firstWord.compare("cd") == 0){
        return new ChangeDirCommand(cmd_line, &plastPwd);
    }
    else if (firstWord.compare("fg") == 0){
        return new ForegroundCommand(cmd_line,jobs);
    }
    else if (firstWord.compare("quit") == 0){
        return new QuitCommand(cmd_line,jobs);
    }else {
        
    }
    return nullptr;

}


void SmallShell::executeCommand(const char *cmd_line) {
    Command* cmd = CreateCommand(cmd_line);
    if (jobs != nullptr){
        jobs->removeFinishedJobs();
    }
    if ( cmd != nullptr){
        cmd->execute();
    }
    // Please note that you must fork smash process for some commands (e.g., external commands....)
}

Command::Command(const char *cmd_line) {
    cmdString = cmd_line;
    argv = new char*[COMMAND_MAX_ARGS];
    argc = _parseCommandLine(cmd_line, argv);
}

BuiltInCommand::BuiltInCommand(const char *cmd_line) : Command(cmd_line) {}

ShowPidCommand::ShowPidCommand(const char *cmd_line) : BuiltInCommand(cmd_line) {}

void ShowPidCommand::execute()
{
    std::cout << getpid() << std::endl;
}

GetCurrDirCommand::GetCurrDirCommand(const char *cmd_line) : BuiltInCommand(cmd_line) {}

void GetCurrDirCommand::execute()
{
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) != nullptr) {
        std::cout << cwd << std::endl;
    } else {
        perror("smash error: getcwd failed");
    }
}

ChangeDirCommand::ChangeDirCommand(const char *cmd_line, char **plastPwd) : BuiltInCommand(cmd_line), plastPwd(plastPwd){}

void ChangeDirCommand::execute()
{
    if (argc > 2){
        std::cout << "smash error:cd:too many arguments"<< std::endl;
        return;
    }else if (argc == 1){
        return;
    }else if ((std::strcmp(argv[1], "-") == 0)){
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == nullptr){
            perror("smash error: getcwd failed");
        } else {
            char* saved_old_path = new char[std::strlen(cwd) + 1];
            std::strcpy(saved_old_path, cwd);
            if (*plastPwd == nullptr){
                std::cout << "smash error: cd: OLDPWD not set" << std::endl;
                *plastPwd = saved_old_path;
                return;
            }else{
                const char* path = *plastPwd;
                if (chdir(path) == 0) {
                    delete[] *plastPwd;
                    *plastPwd = saved_old_path;
                    return;
                } else {
                    delete[] saved_old_path;
                    perror("smash error: chdir failed");
                } 
            }
        }
    }else {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == NULL){
            perror("smash error: getcwd failed");
        } else {
            char* saved_old_path = new char[std::strlen(cwd) + 1];
            std::strcpy(saved_old_path, cwd);
            const char* path = argv[1];
            if (chdir(path) == 0) {
                if (plastPwd == nullptr){
                    *plastPwd = saved_old_path;
                }else {
                    delete[] *plastPwd;
                    *plastPwd = saved_old_path;
                }
                return;
            } else {
                delete[] saved_old_path;
                perror("smash error: chdir failed");
            } 
        }
    }
}



char *SmallShell::getplastPwd()
{
    return plastPwd;
}

Command::~Command()
{

}

BuiltInCommand::~BuiltInCommand()
{

}

ChangeDirCommand::~ChangeDirCommand()
{

}


void JobsList::addJob(Command *cmd, int pid)
{
    // 1. Get the command string properly
    std::string comdLineString = cmd->getString(); 

    // 2. Create unique_ptr using 'new'
    std::unique_ptr<JobEntry> newJob(new JobEntry(cmd, pid, comdLineString));
    
    // 3. Update logic
    removeFinishedJobs(); 
    
    maxJobID++; // Increment first
    jobMap.insert(std::make_pair(maxJobID, std::move(newJob)));
}


void JobsList::printJobsList()
{
    removeFinishedJobs(); // update max in this func
    for (const auto& element : jobMap) {
        int jobId = element.first; 
        
        const std::string cmdLineToPrint = (element.second)->cmdLine; 

        std::cout << "[" << jobId << "] " << cmdLineToPrint << std::endl;
    }
}

void JobsList::removeFinishedJobs()
{
    for (auto& element : jobMap) {
        int jobId = element.first;
        int pidToCheck =  element.second->pid;
        int status;
        int result = waitpid(pidToCheck, &status, WNOHANG);
        if (result > 0 && (WIFEXITED(status) || WIFSIGNALED(status) || WIFSTOPPED(status))){
            jobMap.erase(jobId);
        }
    }
    maxJobID = jobMap.rbegin()->first;
}

void JobsList::removeJobById(int jobId)
{
    auto it = jobMap.find(jobId);
    if (it != jobMap.end()) {
        jobMap.erase(it);
    }
    maxJobID = jobMap.rbegin()->first;
}

void JobsCommand::execute()
{
    jobs->printJobsList();
}

void ForegroundCommand::execute()
{   
    int value;
    if (argc > 2){
        std::cout << "smash error: fg: invalid arguments" << std::endl;
        return;
    } if (argc == 1){
        JobsList::JobEntry* jobToFinish = jobs->getJobById(jobs->getMaxJobID());
        if (jobToFinish == nullptr){
            std::cout << "smash error: fg: jobs list is empty" << std::endl;
            return;
        }
        int jobPID = jobToFinish->pid;
        waitpid(jobPID, NULL, 0);
        ///do i need to check the status?? and the result ??
        jobs->removeJobById(jobs->getMaxJobID());
    }  else if(get_positive_integer_value_legacy(argv[2], &value)){
        JobsList::JobEntry* jobToFinish = jobs->getJobById(value);
        if (jobToFinish == nullptr){
            std::cout << "smash error: fg: job-id " << value << " does not exist" << std::endl;
            return;
        }
        int jobPID = jobToFinish->pid;
        int status;
        pid_t result = waitpid(jobPID, &status, 0);
        ///do i need to check the status??
        jobs->removeJobById(value);
    } else {
        std::cout << "smash error: fg: invalid arguments" << std::endl;
    }
}

JobsList::JobEntry* JobsList::getJobById(int jobId)
{
    auto it = jobMap.find(jobId);
    if (it != jobMap.end()) {
        return it->second.get();
    } else {
        return nullptr;
    }
}

int JobsList::getMaxJobID(){
    return maxJobID;
}

void JobsList::killAllJobs()
{
    std::cout << "smash: sending SIGKILL signal to " << jobMap.size() << "jobs:" << std::endl;
    for (const auto& element : jobMap) {
        int elemPid = (element.second)->pid;
        const std::string cmdLineToPrint = (element.second)->cmdLine; 
        std::cout << elemPid << ": " << cmdLineToPrint << std::endl;
        kill(elemPid, 9); 
    }
}

void QuitCommand::execute()
{
    if((std::strcmp(argv[1], "kill") == 0) && argc >=2){
    jobs->killAllJobs();
    }
    exit(0);
}

void KillCommand::execute()
{
    if(argc != 3){
        std::cout << "smash error: kill: invalid arguments" << std::endl;
        return;
    }

    char* signum_arg = argv[1]; 
    int sigNum;
    int pidNum;
    if (signum_arg[0] == '-' && get_positive_integer_value_legacy(argv[1]+1 , &sigNum )
        && get_positive_integer_value_legacy(argv[2] , &pidNum )){
        JobsList::JobEntry* jobToFinish = jobs->getJobById(pidNum);
        if (jobToFinish == nullptr){
            std::cout << "smash error: fg: job-id " << pidNum << " does not exist" << std::endl;
            return;
        }
        if (kill(pidNum,sigNum) == -1){
            perror("smash error: kill failed");
        }
        std::cout << "signal number" << sigNum << " was sent to pid " << pidNum << std::endl;  
    } else {
        std::cout << "smash error: kill: invalid arguments" << std::endl;
        return;
    }
}

std::string Command::getString()
{
    return cmdString;
}

JobsList::JobEntry::~JobEntry()
{

}

bool checkComplexExternal(std::string cmd_line){
    for (int i=0 ; i < COMMAND_MAX_LENGTH; i++){
        if (cmd_line[i] == '?' || cmd_line[i] == '*'){
            return true;
        }
    }
    return false; 
}


void ExternalCommand::execute()
{
    bool checkBg = false;
    if(argc >= 1){
        char* lastWord = argv[argc - 1];
    
        while(lastWord != nullptr){
            lastWord++;
            if(*lastWord == '&'){
                checkBg = true;
            } else{
                checkBg = false;
            }
        } 
    }

    if (checkComplexExternal(cmdString)){
        char* tempArgv[4];
        tempArgv[0] = (char*)"/bin/bash"; 
        tempArgv[1] = (char*)"-c";
        tempArgv[2] = const_cast<char*>(cmdString.c_str());
        tempArgv[3] = nullptr;

        pid_t pid = fork();

        if (pid == 0){
            execv("/bin/bash", tempArgv);
            perror("smash error: execvp failed");
            exit(1);
        } else if (pid == -1) {
            perror("smash error: fork failed");
        } else {
            if(checkBg == false){
                wait(NULL);
            } else {
              jobs->addJob(this, pid);
            }
        }
    
    } else {
        pid_t pid = fork();
        if (pid == 0){
            execvp(argv[0], argv);
            perror("smash error: execvp failed");
            exit(1);
        } else if (pid == -1) {
            perror("smash error: fork failed");
        } else {
            if(checkBg == false){
                wait(NULL);
            } else {
              jobs->addJob(this, pid);
            }
        }
    }
}

ExternalCommand::ExternalCommand(const char *cmd_line, JobsList *jobs) : Command(cmd_line), jobs(jobs){
}
