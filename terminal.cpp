#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <unistd.h>
#include <set>
#include <cctype>
#include <system_error>
#include <cstdlib>
#include <chrono>
#include <thread>



using namespace std; 
namespace fs = std::filesystem;
fs:: path desktop();
fs::path windowsDesktop();
void not_main();
void look_at_directory();




int main(){
    look_at_directory();
    return 0;
}



//this checks the operating system and sees if it lines up with either mac of windows
std::string getOS() {
    #if defined(_WIN32) || defined(_WIN64)
        return "Windows";
    #elif defined(__APPLE__) || defined(__MACH__)
        return "macOS";
    #else 
        return "unknown";
    #endif 
}


//the next three methods get a certain file path for the OS
fs::path desktop(){
    const char* user = std::getenv("HOME");
    return fs::path(user) / "Desktop";
}

fs::path MAC(){
    const char* user = std::getenv("Macintosh HD");
    return fs::path(user)/ "Users";
}

fs::path windowsDesktop(){
    const char* user = std::getenv("USERPROFILE");
    return fs::path(user) / "Desktop";
}
        


bool check_directory(const fs::path& dir, const string& filename){
    if (!fs::is_directory(dir)){
        return false;
    }
    for(const auto& entry : fs::directory_iterator(dir)){
        if(entry.is_regular_file() && entry.path().filename() == filename){
            return true;
        }
    }
    return false;
    
}

//the boss method, able to gather the directories and then deal woth the user input to go forward into one or back
//need to add the ability to go into files and read them
void look_at_directory(){
    string os = getOS();
    fs::path directory = desktop().parent_path();
    if (os == "macOS"){
        fs::path directory = desktop().parent_path();
        cout << directory << "\n";
        string task;
        
        while (true){
            cout << ">> ";
        getline(cin,task);
            if(task == "ls"){
                for(const auto& file : fs::directory_iterator(directory)){
                    cout << (fs::is_directory(file) ? "[DIR] " : " ");
                    cout << file.path().filename(); 
                    cout << "\n";
                }
                
            }
            else if (task == "exit"){
                break;
            }
            else if (task == "cd .."){
                directory = directory.parent_path();
                cout << directory << "\n";
            }
            else if (task.substr(0,3) == "cd "){
                string folder = task.substr(3);
                fs::path new_path = directory / folder;
                if (fs::exists(new_path) && fs::is_directory(new_path)){
                    directory = new_path;
                    cout << directory << "\n";
                }
                else{
                    cout << "Directory not found " << folder << "\n";
                }
            }
            
            
        }
        cout << ">> ";
        
    }

}


