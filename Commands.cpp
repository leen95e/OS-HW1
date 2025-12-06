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
#include <regex>
#include <sys/syscall.h>



#include <time.h>    // For localtime, strftime, time
#include <stdlib.h>  // For atof
#include <dirent.h>

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





SmallShell::SmallShell(): plastPwd(nullptr), aliasMap(), aliasList(), fgPID(-1) {
    jobs = new JobsList();
}



SmallShell::~SmallShell() {
    delete jobs; // <--- ADD THIS LINE
    // You should also delete plastPwd if it's not null and was allocated with new char[]
    if (plastPwd != nullptr) {
        delete[] plastPwd;  
    }
}

/**
* Creates and returns a pointer to Command class which matches the given command line (cmd_line)
*/
Command *SmallShell::CreateCommand(const char *cmd_line) {
    std::string ogCommand = cmd_line;

    string commandLine = _trim(string(cmd_line));
    string firstWord = commandLine.substr(0, commandLine.find_first_of(" \n"));
    auto it = aliasMap.find(firstWord);
    if (it != aliasMap.end()) {
        commandLine.replace(0, commandLine.find(' '), it->second);
        commandLine = _trim(string(commandLine));
        firstWord = commandLine.substr(0, commandLine.find_first_of(" \n"));
    };
    if (firstWord.compare("alias") == 0){
        return new AliasCommand(commandLine.c_str(), ogCommand, &aliasMap, &aliasList);
    }
    if (commandLine.find('>') != string::npos){
        return new RedirectionCommand(commandLine.c_str(), ogCommand);
    }
    if (commandLine.find('|') != string::npos){
        return new PipeCommand(commandLine.c_str(), ogCommand);
    }

    if (firstWord.compare("pwd") == 0) {
      return new GetCurrDirCommand(commandLine.c_str(), ogCommand);
    }
    else if (firstWord.compare("showpid") == 0) {
      return new ShowPidCommand(commandLine.c_str(), ogCommand);
    }
    else if (firstWord.compare("jobs") == 0){
        return new JobsCommand(commandLine.c_str(), ogCommand, jobs);
    }
    else if (firstWord.compare("cd") == 0){
        return new ChangeDirCommand(commandLine.c_str(), ogCommand, &plastPwd);
    }
    else if (firstWord.compare("fg") == 0){
        return new ForegroundCommand(commandLine.c_str(), ogCommand, jobs, &fgPID);
    }
    else if (firstWord.compare("quit") == 0){
        return new QuitCommand(commandLine.c_str(), ogCommand, jobs);
    }
    else if (firstWord.compare("kill") == 0){
        return new KillCommand(commandLine.c_str(), ogCommand, jobs);
    }
    else if (firstWord.compare("unalias") == 0){
        return new UnAliasCommand(commandLine.c_str(), ogCommand, &aliasMap, &aliasList);
    }
    else if (firstWord.compare("unsetenv") == 0){
        return new UnSetEnvCommand(commandLine.c_str(), ogCommand);
    }
    else if (firstWord.compare("sysinfo") == 0){
        return new SysInfoCommand(commandLine.c_str(), ogCommand);
    }
    else if (firstWord.compare("du") == 0){
        return new DiskUsageCommand(commandLine.c_str(), ogCommand);
    }
    else if (firstWord.compare("whoami") == 0){
        return new WhoAmICommand(commandLine.c_str(), ogCommand);
    }
    else {
        bool checkBg = _isBackgroundComamnd(commandLine.c_str());
        std::string trimmed_cmd = _rtrim(commandLine);
        if(checkBg == true){
            trimmed_cmd.pop_back(); // Removes the last character ('&')
            commandLine = trimmed_cmd;
        }
        return new ExternalCommand(commandLine.c_str(), ogCommand, jobs, checkBg, &fgPID);
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

Command::Command(const char *cmd_line, std::string cmdString): cmdString(cmdString) {
    argv = new char*[COMMAND_MAX_ARGS];
    argc = _parseCommandLine(cmd_line, argv);
}

BuiltInCommand::BuiltInCommand(const char *cmd_line, std::string cmdString) : Command(cmd_line, cmdString) {}

ShowPidCommand::ShowPidCommand(const char *cmd_line, std::string cmdString) : BuiltInCommand(cmd_line, cmdString) {}

void ShowPidCommand::execute()
{
    std::cout << "smash pid is " <<  getpid() << std::endl;
}

GetCurrDirCommand::GetCurrDirCommand(const char *cmd_line, std::string cmdString) : BuiltInCommand(cmd_line, cmdString) {}

void GetCurrDirCommand::execute()
{
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) != nullptr) {
        std::cout << cwd << std::endl;
    } else {
        perror("smash error: getcwd failed");
    }
}

ChangeDirCommand::ChangeDirCommand(const char *cmd_line, std::string cmdString, char **plastPwd) : BuiltInCommand(cmd_line, cmdString), plastPwd(plastPwd){}

void ChangeDirCommand::execute()
{
    if (argc > 2){
        std::cerr << "smash error: cd: too many arguments"<< std::endl;
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
                std::cerr << "smash error: cd: OLDPWD not set" << std::endl;
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
    for (int i = 0; i < argc; ++i) {
        if (argv[i] != nullptr) {
            free(argv[i]); // Must use free() since malloc() was used
        }
    }
    // 2. Delete the array of pointers (allocated with new char*[] in Command::Command)
    delete[] argv;
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
    removeFinishedJobs();
    if (jobMap.size() == 0){
        return;
    } // update max in this func
    for (const auto& element : jobMap) {
        int jobId = element.first; 
        
        const std::string cmdLineToPrint = (element.second)->cmdLine; 

        std::cout << "[" << jobId << "] " << cmdLineToPrint << std::endl;
    }
}

void JobsList::removeFinishedJobs()
{
    if (jobMap.size() == 0){
        return;
    }
    for (auto& element : jobMap) {
        int jobId = element.first;
        int pidToCheck =  element.second->pid;
        int status;
        int result = waitpid(pidToCheck, &status, WNOHANG);
        if (result > 0 && (WIFEXITED(status) || WIFSIGNALED(status) || WIFSTOPPED(status))){
            jobMap.erase(jobId);
        }
    }
    if (jobMap.size() == 0){
        maxJobID = 0;
        return;
    }
    maxJobID = jobMap.rbegin()->first;
}

void JobsList::removeJobById(int jobId)
{
    auto it = jobMap.find(jobId);
    if (it != jobMap.end()) {
        jobMap.erase(it);
    }
    if (jobMap.size() == 0){
        maxJobID = 0;
        return;
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
        std::cerr << "smash error: fg: invalid arguments" << std::endl;
        return;
    } if (argc == 1){
        JobsList::JobEntry* jobToFinish = jobs->getJobById(jobs->getMaxJobID());
        if (jobToFinish == nullptr){
            std::cerr << "smash error: fg: jobs list is empty" << std::endl;
            return;
        }
        int jobPID = jobToFinish->pid;
        std::cout << jobToFinish->cmdLine << " " << jobPID << std::endl;
        *fgPID = jobPID;
        waitpid(jobPID, NULL, 0);
        *fgPID = -1;
        jobs->removeJobById(jobs->getMaxJobID());
    }  else if(get_positive_integer_value_legacy(argv[1], &value)){
        JobsList::JobEntry* jobToFinish = jobs->getJobById(value);
        if (jobToFinish == nullptr){
            std::cerr << "smash error: fg: job-id " << value << " does not exist" << std::endl;
            return;
        }
        int jobPID = jobToFinish->pid;
        int status;
        std::cout << jobToFinish->cmdLine << " " << jobPID << std::endl;
        *fgPID = jobPID;
        waitpid(jobPID, &status, 0);
        *fgPID = -1;
        jobs->removeJobById(value);
        
    } else {
        std::cerr << "smash error: fg: invalid arguments" << std::endl;
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
    std::cout << "smash: sending SIGKILL signal to " << jobMap.size() << " jobs:" << std::endl;
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
    //neeed to call al destructors
    exit(0);
}

void KillCommand::execute()
{
    if(argc != 3){
        std::cerr << "smash error: kill: invalid arguments" << std::endl;
        return;
    }

    char* signum_arg = argv[1]; 
    int sigNum;
    int jobpidNum;
    if (signum_arg[0] == '-' && get_positive_integer_value_legacy(argv[1]+1 , &sigNum )
        && get_positive_integer_value_legacy(argv[2] , &jobpidNum )){
        JobsList::JobEntry* jobToFinish = jobs->getJobById(jobpidNum);
        if (jobToFinish == nullptr){
            std::cerr << "smash error: kill: job-id " << jobpidNum << " does not exist" << std::endl;
            return;
        }
        if (kill(jobToFinish->pid,sigNum) == -1){
            perror("smash error: kill failed");
            return;
        }
        std::cout << "signal number " << sigNum << " was sent to pid " << jobToFinish->pid << std::endl;  
    } else {
        std::cerr << "smash error: kill: invalid arguments" << std::endl;
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
    for (int i=0 ; i < cmd_line.size() ; i++){
        if (cmd_line[i] == '?' || cmd_line[i] == '*'){
            return true;
        }
    }
    return false; 
}


void ExternalCommand::execute()
{
    string trimmed_cmd = _rtrim(realCommand.c_str());
    if (checkComplexExternal(cmdString)){
        char* tempArgv[4];
        tempArgv[0] = (char*)"/bin/bash"; 
        tempArgv[1] = (char*)"-c";
        tempArgv[2] = const_cast<char*>(trimmed_cmd.c_str());
        tempArgv[3] = nullptr;

        pid_t pid = fork();

        if (pid == 0){
            setpgrp();
            if (execv((char*)"/bin/bash", tempArgv) < 0){
                perror("smash error: execv failed");
                exit(1);
            }

        } else if (pid < 0) {
            perror("smash error: fork failed");
            return;
        } else {
            if(isBg == false){
                *fgPID = pid;
                waitpid(pid, NULL,0);
                *fgPID = -1;
            } else {
              jobs->addJob(this, pid);
            }
        }
    
    } else {
        pid_t pid = fork();
        if (pid == 0){
            setpgrp();
            if (execvp(argv[0], argv) < 0){
                perror("smash error: execvp failed");
                exit(1);
            }
        } else if (pid == -1) {
            perror("smash error: fork failed");
        } else {
            if(isBg == false){
                *fgPID = pid;
                waitpid(pid, NULL,0);
                *fgPID = -1;
            } else {
              jobs->addJob(this, pid);
            }
        }
    }
}

ExternalCommand::ExternalCommand(const char *cmd_line, std::string cmdString, JobsList *jobs, bool isBg, int* fgPID) :
                                 Command(cmd_line, cmdString), jobs(jobs), isBg(isBg), realCommand(cmd_line), fgPID(fgPID){
}

AliasCommand::AliasCommand(const char *cmd_line, std::string cmdString, std::map<std::string, std::string> *aliasMap,
                         std::list<std::string> *aliasList) : BuiltInCommand(cmd_line, cmdString), aliasMap(aliasMap), aliasList(aliasList){}

void AliasCommand::execute()
{
    std::list<std::string> keyWords = {"chprompt", "showpid", "pwd", "cd", "jobs", "fg", 
                                        "quit", "kill", "alias", "unalias", "unsetenv", "sysinfo", "whoami", "du", "usbinfo"};
    const std::regex alias_pattern("^alias [a-zA-Z0-9_]+='[^']*'$");
    if (argc == 1){
            for (const auto& element : *aliasList){
                std::cout <<  element << std::endl;
            }
        return;        
    }
    if (std::regex_match(_trim(cmdString), alias_pattern)) {
        int equalsPos = cmdString.find('=');
        std::string name = cmdString.substr(6, equalsPos - 6);
        int quoteStart = equalsPos + 2; 
        int quoteEnd = cmdString.length() - 1;
        std::string commandName = cmdString.substr(quoteStart, quoteEnd - quoteStart);
        for (const auto& element : keyWords){
            if(element.compare(name) == 0){
                std::cerr << "smash error: alias: " << name << " already exists or is a reserved command" << std::endl;
                return;
            } 
        }
        if (aliasMap->find(name) != aliasMap->end()){
            std::cerr << "smash error: alias: " << name << " already exists or is a reserved command" << std::endl;
            return;
        }
        aliasMap->insert(std::make_pair(name, commandName));
        aliasList->push_back(cmdString.substr(6, cmdString.size()));
    } else {
        std::cerr << "smash error: alias: invalid alias format" << std::endl;
        return;
    }
}

QuitCommand::QuitCommand(const char *cmd_line, std::string cmdString, JobsList *jobs): BuiltInCommand(cmd_line, cmdString), jobs(jobs){}

JobsList::JobEntry::JobEntry(Command *cmd, int pid, std::string cmdLine): cmd(cmd), pid(pid), cmdLine(cmdLine){}

JobsCommand::JobsCommand(const char * cmd_line, std::string cmdString, JobsList * jobs): BuiltInCommand(cmd_line, cmdString), jobs(jobs) {}

KillCommand::KillCommand(const char *cmd_line, std::string cmdString, JobsList *jobs): BuiltInCommand(cmd_line, cmdString), jobs(jobs){}

ForegroundCommand::ForegroundCommand(const char *cmd_line, std::string cmdString, JobsList *jobs, int* fgPID):  BuiltInCommand(cmd_line, cmdString), jobs(jobs), fgPID(fgPID){
}

UnAliasCommand::UnAliasCommand(const char *cmd_line, std::string cmdString, std::map<std::string , std::string>* aliasMap ,
                            std::list<std::string>* aliasList) : BuiltInCommand(cmd_line, cmdString), aliasMap(aliasMap), aliasList(aliasList) {}

void UnAliasCommand::execute()
{
    if(argc < 2){
        std::cerr << "smash error: unalias: not enough arguments" << std::endl;
    }
    for(int i = 1 ; i < argc ; i++){
        auto it = aliasMap->find(argv[i]);
        if(it == aliasMap->end()){
            std::cerr << "smash error: unalias: " << argv[i] << " alias does not exist" << std::endl;
            return;
        } else {
            std::string full_definition = it->first + "='" + it->second + "'";
            for (auto list_it = aliasList->begin(); list_it != aliasList->end();) {
                if (*list_it == full_definition) {
                    list_it = aliasList->erase(list_it); 
                    break; 
                } else {
                    ++list_it;
                }
            }
        }
        aliasMap->erase(argv[i]);
    }
}

JobsList::~JobsList()
{

}

UnSetEnvCommand::UnSetEnvCommand(const char *cmd_line, std::string cmdString) : BuiltInCommand(cmd_line, cmdString){}

void UnSetEnvCommand::execute()
{
    if (argc < 2) {
        std::cerr << "smash error: unsetenv: not enough arguments" << std::endl;
        return;
    }
    std::string path = "/proc/" + to_string(getpid()) + "/environ";
    int fd = open(path.c_str(),O_RDONLY);
    if (fd == -1) {
        perror("smash error: open failed");
        return;
    }
    char buffer[BUFFER_MAX];
    int bytesRead = read(fd, buffer, BUFFER_MAX);
    if (bytesRead < 0){
        perror("smash error: read failed");
        if (close(fd) < 0){
            perror("smash error: close failed");
        }
        return;
    }
    if (close(fd) < 0){
        perror("smash error: close failed");
        return;
    }
    for (int i = 1; i < argc; ++i) {
        int index = 0;
        bool foundIt = 0;
        while (index < bytesRead){
            string toCheck = &buffer[index];
            size_t equal = toCheck.find('=');
            if (equal != string::npos){
                string isValid = toCheck.substr(0, equal);
                if (isValid.compare(argv[i]) == 0){
                    foundIt = 1;
                    break;
                }
            }
            index += toCheck.size() + 1;
        }
        if (foundIt == false){
            cerr << "smash error: unsetenv: " << argv[i] << " does not exist" << endl;
            return;
        }
        int pos = -1;
        int varNameSize = strlen(argv[i]);
        for (int j = 0; __environ[j]; j++){
            if((strncmp(argv[i], __environ[j], varNameSize) == 0) && (__environ[j][varNameSize] == '=')){
                pos = j;
                break;
            }
        }
        ///////////////DIAMAMAMAMAMAMA DIMA
        for (int j = pos; __environ[j]; j++){
            __environ[j] =  __environ[j+1];
        }
    }
}


   











SysInfoCommand::SysInfoCommand(const char *cmd_line, std::string cmdString) : BuiltInCommand(cmd_line, cmdString){}

int SysInfoCommand::read_from_file(const char* filepath, char* buffer, size_t size) {
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        return -1; 
    }

    ssize_t bytes_read = read(fd, buffer, size - 1);
    if (bytes_read < 0) {
        if (close(fd) < 0){
            return -2;
        }
        return -3;
    }

    buffer[bytes_read] = '\0'; 
    
    if (bytes_read > 0 && buffer[bytes_read - 1] == '\n') {
        buffer[bytes_read - 1] = '\0';
    }

    if (close(fd) < 0){
        return -2;
    }
    return bytes_read;
}

void SysInfoCommand::execute() {
    char buffer[BUFFER_MAX];

    if (read_from_file("/proc/sys/kernel/ostype", buffer, sizeof(buffer)) == -1) {
        perror("smash error: open failed"); 
        return;
    } else if (read_from_file("/proc/sys/kernel/ostype", buffer, sizeof(buffer)) == -2){
        perror("smash error: close failed"); 
        return;
    }else if (read_from_file("/proc/sys/kernel/ostype", buffer, sizeof(buffer)) == -3){
        perror("smash error: read failed"); 
        return;
    }
    std::cout << "System: " << buffer << std::endl;

    if (read_from_file("/proc/sys/kernel/hostname", buffer, sizeof(buffer)) == -1) {
        perror("smash error: open failed");
        return;
    }else if (read_from_file("/proc/sys/kernel/hostname", buffer, sizeof(buffer)) == -2) {
        perror("smash error: close failed");
        return;
    }else if (read_from_file("/proc/sys/kernel/hostname", buffer, sizeof(buffer)) == -3) {
        perror("smash error: read failed");
        return;
    }

    std::cout << "Hostname: " << buffer << std::endl;

    if (read_from_file("/proc/sys/kernel/osrelease", buffer, sizeof(buffer)) == -1) {
        perror("smash error: open failed");
        return;
    }else if (read_from_file("/proc/sys/kernel/osrelease", buffer, sizeof(buffer)) == -2) {
        perror("smash error: close failed");
        return;
    }else if (read_from_file("/proc/sys/kernel/osrelease", buffer, sizeof(buffer)) == -3) {
        perror("smash error: read failed");
        return;
    }

    std::cout << "Kernel: " << buffer << std::endl;

    std::cout << "Architecture: x86_64" << std::endl;

    if (read_from_file("/proc/uptime", buffer, sizeof(buffer)) == -1) {
        perror("smash error: open failed");
        return;
    }else if (read_from_file("/proc/uptime", buffer, sizeof(buffer)) == -2) {
        perror("smash error: close failed");
        return;
    }else if (read_from_file("/proc/uptime", buffer, sizeof(buffer)) == -3) {
        perror("smash error: read failed");
        return;
    }
    //////////////////////////////// time //////////////////
    char* space_pos = strchr(buffer, ' ');
    if (space_pos != NULL) {
        *space_pos = '\0';
    }

    double uptime_seconds = atof(buffer); // המרה למספר
    time_t current_time = time(NULL);
    time_t boot_time_t = current_time - (time_t)uptime_seconds;
    struct tm* boot_tm = localtime(&boot_time_t);
    char time_buffer[80];
    
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", boot_tm);
    std::cout << "Boot Time: " << time_buffer << std::endl;
}

RedirectionCommand::RedirectionCommand(const char *cmd_line, std::string cmdString) : Command(cmd_line, cmdString)
{
    isOverride = false;
    size_t pos = cmdString.find('>');
    if (cmdString[pos + 1] == '>'){
        filePath = cmdString.substr(pos + 2);
    }else {
        isOverride = true;
        filePath = cmdString.substr(pos + 1);
    }
    filePath = _trim(filePath);
    commandLine = cmdString.substr(0, pos);
    bool checkBg = _isBackgroundComamnd(commandLine.c_str());
    std::string trimmed_cmd = _rtrim(commandLine);
    if(checkBg == true){
        trimmed_cmd.pop_back(); // Removes the last character ('&')
        commandLine = trimmed_cmd;
    }
    
}

void RedirectionCommand::execute()
{
    int oldFd = dup(STDOUT_FILENO);
    if (oldFd < 0 ){
        perror("smash error: dup failed");
        return;
    }
    int newFd;
    if (isOverride){
        newFd = open (filePath.c_str(), O_WRONLY | O_CREAT | O_TRUNC ,0644);
        if (newFd < 0){
            perror("smash error: open failed");
            if (close(oldFd) < 0){
                perror("smash error: close failed");
            }
            return;
        }
        if (dup2(newFd, STDOUT_FILENO) < 0){
            perror("smash error: dup2 failed");
            if (close(oldFd) < 0){
                perror("smash error: close failed");
            } 
            if (close(newFd) < 0){
                perror("smash error: close failed");
            }
            return;
        }
    } else {
        newFd = open (filePath.c_str(), O_WRONLY | O_CREAT | O_APPEND ,0666);
        if (newFd < 0){
            perror("smash error: open failed");
            if (close(oldFd) < 0){
                perror("smash error: close failed");
            }
            return;
        }
        if (dup2(newFd, STDOUT_FILENO) < 0){
            perror("smash error: dup2 failed");
            if (close(oldFd) < 0){
                perror("smash error: close failed");
            } 
            if (close(newFd) < 0){
                perror("smash error: close failed");
            }
            return;
        }
    }
    SmallShell& smash = SmallShell::getInstance();
    smash.executeCommand(commandLine.c_str());

    if (dup2(oldFd, STDOUT_FILENO) < 0){
        perror("smash error: dup2 failed");
    }
    if (close(oldFd) < 0){
        perror("smash error: close failed");
    } 
}

PipeCommand::PipeCommand(const char *cmd_line, std::string cmdString) : Command(cmd_line, cmdString)
{
    isBg = false;
    string commands = cmd_line;
    size_t pos = commands.find('|');
    if (commands[pos + 1] == '&'){
        command2 = _trim(commands.substr(pos + 3));
        isBg = true;
    }else {
        command2 = _trim(commands.substr(pos + 2));
    }
    command1 = commands.substr(0, pos);
    bool checkBg1 = _isBackgroundComamnd(command1.c_str());
    std::string trimmed_cmd1 = _rtrim(command1);
    if(checkBg1 == true){
        trimmed_cmd1.pop_back(); // Removes the last character ('&')
        command1 = trimmed_cmd1;
    }

    bool checkBg2 = _isBackgroundComamnd(command2.c_str());
    std::string trimmed_cmd2 = _rtrim(command2);
    if(checkBg2 == true){
        trimmed_cmd2.pop_back(); // Removes the last character ('&')
        command2= trimmed_cmd2;
    }

}

void PipeCommand::execute()
{

    int fd[2];
    if(pipe(fd) < 0){
        perror("smash error: pipe failed");
        return;
    }
    SmallShell& smash = SmallShell::getInstance();
    pid_t pid1 = fork();
    if(pid1 < 0){
        perror("smash error: fork failed");
        return;
    }

    if (pid1 == 0) {
    if(isBg) {
        if(dup2(fd[1], STDERR_FILENO) < 0){
            perror("smash error: dup2 failed");
            return;
        }
    }else { 
        if(dup2(fd[1], STDOUT_FILENO) < 0){
            perror("smash error: dup2 failed");
            return;
        }
    }
    if(close(fd[0]) < 0 ){
        perror("smash error: close failed");
        return;
    }
    if(close(fd[1]) < 0 ){
        perror("smash error: close failed");
        return;
    }
    smash.executeCommand(command1.c_str());
    exit(0);
    }

    pid_t pid2 = fork();
    if(pid2 < 0){
        perror("smash error: fork failed");
        return;
    }
    if (pid2 == 0) {
    if(dup2(fd[0], STDIN_FILENO) < 0){
        perror("smash error: dup2 failed");
        return;
    }

    if(close(fd[0]) < 0 ){
        perror("smash error: close failed");
        return;
    }
    if(close(fd[1]) < 0 ){
        perror("smash error: close failed");
        return;
    }
    smash.executeCommand(command2.c_str());
    exit(0);
    }

    if(close(fd[0]) < 0 ){
        perror("smash error: close failed");
        return;
    }
    if(close(fd[1]) < 0 ){
        perror("smash error: close failed");
        return;
    }
    waitpid(pid1, nullptr, 0);
    waitpid(pid2, nullptr, 0);

}

WhoAmICommand::WhoAmICommand(const char *cmd_line, std::string cmdString) : Command(cmd_line, cmdString){}

void WhoAmICommand::execute()
{
    uid_t uid = geteuid();
    gid_t gid = getegid();
    char buffer[BUFFER_MAX];
    size_t bytesRead;
    int fd = open("/etc/passwd", O_RDONLY);
    if(fd < 0){
        perror("smash error: open failed");
        return;
    }
    bytesRead = read(fd, buffer, BUFFER_MAX);
    if(bytesRead <= 0){
        perror("smash error: read failed");
        if(close(fd) < 0){
        perror("smash error: close failed");
        return;
    }
    }
    if(close(fd) < 0){
        perror("smash error: close failed");
        return;
    }
    buffer[bytesRead] = '\0';
    stringstream users(buffer);
    string user;
    string username, homeDir;

    while (getline(users, user)) {
        int field = 0;
        bool found = false;
        size_t colonPos = user.find(':');
        while (colonPos != string::npos) {
            if (field == 0) {
                username = user.substr(0, colonPos);
            }
            else if (field == 2) {
                uid_t user_uid = stoi(user.substr(0, colonPos));
                if (uid == user_uid) {
                    found = true;
                }
            }
            else if (field == 5) {
                homeDir = user.substr(0, colonPos);
                
            }
            user = user.substr(colonPos+1);
            field++;
            colonPos = user.find(':');
        }
        if(found){
            break;
        }
    }
    cout << username << endl;
    cout << uid << endl;
    cout << gid << endl;
    cout << homeDir << endl;
}

DiskUsageCommand::DiskUsageCommand(const char *cmd_line, std::string cmdString) : Command(cmd_line, cmdString), isError(false)
{
}


struct linux_dirent {
    long           d_ino;
    off_t          d_off;
    unsigned short d_reclen;
    char           d_name[];
};

int DiskUsageCommand::recursivelyGetUsage(std::string path)
{
    struct linux_dirent *d;
    struct stat st;

    int fd = open(path.c_str(), O_RDONLY | O_DIRECTORY);
    if(fd < 0){
        perror("smash error: open failed");
        isError = true;
        return 0;
    }

    if (stat(path.c_str(), &st) < 0) {
        perror("smash error: stat failed");
        isError = true;
        return 0;
    }
    long total = st.st_blocks * 512;;
    long dirRead;
    char buffer[BUFFER_MAX];
    char dirType;
    while(1){
        dirRead = syscall(SYS_getdents, fd, buffer, BUFFER_MAX);
        if (dirRead < 0) {
            perror("smash error: getdents failed");
            isError = true;
            return 0;
        }
        if (dirRead == 0) {
            break;
        }
        for (int dirPos = 0; dirPos < dirRead;) {
            d = (struct linux_dirent *)(buffer + dirPos);
            dirType = *(buffer + dirPos + d->d_reclen - 1);
            if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0) {
                dirPos += d->d_reclen;
                continue;
            }
            if (dirType == DT_LNK) {
                dirPos += d->d_reclen;
                continue;
            }
            else if (dirType == DT_REG) {
                struct stat st;
                string file_path = path + "/" + string(d->d_name);
                if (stat(file_path.c_str(), &st) < 0) {
                    perror("smash error: stat failed");
                    isError = true;
                    return total;
                } 
                total += st.st_blocks * 512;
            } 
            else if (dirType == DT_DIR) {
                string dirPath = path + "/" + string(d->d_name);
                total += recursivelyGetUsage(dirPath);
                if (isError) {
                    return 0;
                }
            }
            dirPos += d->d_reclen;
        }
    }
    if (close(fd) < 0) {
        perror("smash error: close failed");
    }
    return total;
}

void DiskUsageCommand::execute()
{
    string path;
    if (argc > 2) {
        std::cerr << "smash error: du: too many arguments" << endl;
        return;
    }
    if (argc == 1) {
        char* cwd = getcwd(nullptr, 0);
        if (cwd == nullptr) {
            perror("smash error: getcwd failed");
            return;
        }
        path = cwd;
        free(cwd);
    } else {
        path = argv[1];
        int fd = open(path.c_str(), O_RDONLY | O_DIRECTORY);
        if (fd < 0) { 
            perror("smash error: open failed");
            return;
        }
        if (close(fd) < 0) {
            perror("smash error: close failed");
            return;
        }
    }
    long total = (recursivelyGetUsage(path) / 1024);
    if (!isError) {
        cout << "Total disk usage: " << total << " KB" << endl;
    }
}

int SmallShell::getForegroundPid()
{
    return fgPID;
}

