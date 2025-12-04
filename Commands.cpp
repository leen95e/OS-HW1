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


#include <time.h>    // For localtime, strftime, time
#include <stdlib.h>  // For atof

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
SmallShell::SmallShell(): plastPwd(nullptr), aliasMap(), aliasList() {
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
        string cmd_s = _trim(string(commandLine));
        firstWord = cmd_s.substr(0, cmd_s.find_first_of(" \n"));
    };
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
        return new ForegroundCommand(commandLine.c_str(), ogCommand, jobs);
    }
    else if (firstWord.compare("quit") == 0){
        return new QuitCommand(commandLine.c_str(), ogCommand, jobs);
    }
    else if (firstWord.compare("kill") == 0){
        return new KillCommand(commandLine.c_str(), ogCommand, jobs);
    }
    else if (firstWord.compare("alias") == 0){
        return new AliasCommand(commandLine.c_str(), ogCommand, &aliasMap, &aliasList);
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
    else {
        bool checkBg = _isBackgroundComamnd(commandLine.c_str());
        std::string trimmed_cmd = _rtrim(commandLine);
        if(checkBg == true){
            trimmed_cmd.pop_back(); // Removes the last character ('&')
            commandLine = trimmed_cmd;
        }
        return new ExternalCommand(commandLine.c_str(), ogCommand, jobs, checkBg);
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
    std::cout << getpid() << std::endl;
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
        std::cout << "smash error: fg: invalid arguments" << std::endl;
        return;
    } if (argc == 1){
        JobsList::JobEntry* jobToFinish = jobs->getJobById(jobs->getMaxJobID());
        if (jobToFinish == nullptr){
            std::cout << "smash error: fg: jobs list is empty" << std::endl;
            return;
        }
        int jobPID = jobToFinish->pid;
        std::cout << jobToFinish->cmdLine << " " << jobPID << std::endl;
        waitpid(jobPID, NULL, 0);
        jobs->removeJobById(jobs->getMaxJobID());
    }  else if(get_positive_integer_value_legacy(argv[1], &value)){
        JobsList::JobEntry* jobToFinish = jobs->getJobById(value);
        if (jobToFinish == nullptr){
            std::cout << "smash error: fg: job-id " << value << " does not exist" << std::endl;
            return;
        }
        int jobPID = jobToFinish->pid;
        int status;
        std::cout << jobToFinish->cmdLine << " " << jobPID << std::endl;
        waitpid(jobPID, &status, 0);
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
        std::cout << "smash error: kill: invalid arguments" << std::endl;
        return;
    }

    char* signum_arg = argv[1]; 
    int sigNum;
    int jobpidNum;
    if (signum_arg[0] == '-' && get_positive_integer_value_legacy(argv[1]+1 , &sigNum )
        && get_positive_integer_value_legacy(argv[2] , &jobpidNum )){
        JobsList::JobEntry* jobToFinish = jobs->getJobById(jobpidNum);
        if (jobToFinish == nullptr){
            std::cout << "smash error: fg: job-id " << jobpidNum << " does not exist" << std::endl;
            return;
        }
        if (kill(jobToFinish->pid,sigNum) == -1){
            perror("smash error: kill failed");
        }
        std::cout << "signal number " << sigNum << " was sent to pid " << jobToFinish->pid << std::endl;  
    } else {
        std::cout << "smash error: kill: invalid arguments" << std::endl;
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
            if (execv("/bin/bash", tempArgv) < 0){
                perror("smash error: execv failed");
                exit(1);
            }

        } else if (pid < 0) {
            perror("smash error: fork failed");
            return;
        } else {
            if(isBg == false){
                waitpid(pid, NULL,0);
            } else {
              jobs->addJob(this, pid);
            }
        }
    
    } else {
        pid_t pid = fork();
        if (pid == 0){
            setpgrp();
            if (execvp(argv[0], argv)){
                perror("smash error: execvp failed");
                exit(1);
            }
        } else if (pid == -1) {
            perror("smash error: fork failed");
        } else {
            if(isBg == false){
                waitpid(pid, NULL,0);
            } else {
              jobs->addJob(this, pid);
            }
        }
    }
}

ExternalCommand::ExternalCommand(const char *cmd_line, std::string cmdString, JobsList *jobs, bool isBg) : Command(cmd_line, cmdString), jobs(jobs), isBg(isBg), realCommand(cmd_line){
}

AliasCommand::AliasCommand(const char *cmd_line, std::string cmdString, std::map<std::string, std::string> *aliasMap,
                         std::list<std::string> *aliasList) : BuiltInCommand(cmd_line, cmdString), aliasMap(aliasMap), aliasList(aliasList){}

void AliasCommand::execute()
{
    std::list<std::string> keyWords = {"chprompt", "showpid", "pwd", "cd", "jobs", "fg", 
                                        "quit", "kill", "alias", "unalias", "unsetenv", "sysinfo"};
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
                std::cout << "smash error: alias: " << name << " already exists or is a reserved command" << std::endl;
                return;
            } 
        }
        if (aliasMap->find(name) != aliasMap->end()){
            std::cout << "ssmash error: alias: " << name << " already exists or is a reserved command" << std::endl;
            return;
        }
        aliasMap->insert(std::make_pair(name, commandName));
        aliasList->push_back(cmdString.substr(6, cmdString.size()));
    } else {
        std::cout << "smash error: alias: invalid alias format" << std::endl;
        return;
    }
}

QuitCommand::QuitCommand(const char *cmd_line, std::string cmdString, JobsList *jobs): BuiltInCommand(cmd_line, cmdString), jobs(jobs){}

JobsList::JobEntry::JobEntry(Command *cmd, int pid, std::string cmdLine): cmd(cmd), pid(pid), cmdLine(cmdLine){}

JobsCommand::JobsCommand(const char * cmd_line, std::string cmdString, JobsList * jobs): BuiltInCommand(cmd_line, cmdString), jobs(jobs) {}

KillCommand::KillCommand(const char *cmd_line, std::string cmdString, JobsList *jobs): BuiltInCommand(cmd_line, cmdString), jobs(jobs){}

ForegroundCommand::ForegroundCommand(const char *cmd_line, std::string cmdString, JobsList *jobs):  BuiltInCommand(cmd_line, cmdString), jobs(jobs){}

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
            std::cerr << "smash error: unalias: " << argv[i] << " does not exist" << std::endl;
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
        std::cout << "smash error: unsetenv: not enough arguments" << std::endl;
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
            perror("smash error: read failed");
        }
        return;
    }
    if (close(fd) < 0){
        perror("smash error: read failed");
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
        for (int j = 0; __environ[j]; i++){
            if((strncmp(argv[j], __environ[j], varNameSize) == 0) && (__environ[j][varNameSize] == '=')){
                pos = j;
                break;
            }
        }
        for (int j = pos; __environ[j+1]; i++){
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
        close(fd);
        return -1;
    }

    buffer[bytes_read] = '\0'; 
    
    if (bytes_read > 0 && buffer[bytes_read - 1] == '\n') {
        buffer[bytes_read - 1] = '\0';
    }

    close(fd);
    return bytes_read;
}

void SysInfoCommand::execute() {
    char buffer[BUFFER_MAX];

    if (read_from_file("/proc/sys/kernel/ostype", buffer, sizeof(buffer)) < 0) {
        perror("smash error: open failed"); 
        return;
    }
    std::cout << "System: " << buffer << std::endl;

    if (read_from_file("/proc/sys/kernel/hostname", buffer, sizeof(buffer)) < 0) {
        perror("smash error: open failed");
        return;
    }
    std::cout << "Hostname: " << buffer << std::endl;

    if (read_from_file("/proc/sys/kernel/osrelease", buffer, sizeof(buffer)) < 0) {
        perror("smash error: open failed");
        return;
    }
    std::cout << "Kernel: " << buffer << std::endl;

    std::cout << "Architecture: x86_64" << std::endl;

    if (read_from_file("/proc/uptime", buffer, sizeof(buffer)) < 0) {
        perror("smash error: open failed");
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
