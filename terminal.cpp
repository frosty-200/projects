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

//new version able to read files


using namespace std; 
namespace fs = std::filesystem;
fs:: path desktop();
fs::path windowsDesktop();
bool check_directory(const fs::path& dir, const string& filename);
void look_at_directory();




int main(){
    look_at_directory();

    return 0;
}



std::string getOS() {
    #if defined(_WIN32) || defined(_WIN64)
        return "Windows";
    #elif defined(__APPLE__) || defined(__MACH__)
        return "macOS";
    #else 
        return "unknown";
    #endif  // no semicolon here
}


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

void look_at_directory(){
    string os = getOS();
    fs::path directory = desktop().parent_path();
    if (os == "macOS"){
        fs::path directory = desktop().parent_path();
        cout << directory << "\n";
        if(fs::exists(directory) && fs::is_directory(directory)){
            vector<fs::path> files;
            int index = 0;
            for(const auto& i : fs::directory_iterator(directory)){
                if (fs::is_regular_file(i)){
                    cout << "index " << index << " has file " << i.path().filename() << "\n";
                    files.push_back(i);
                    index ++;
                }
            }}
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
                }
                
                else{
                    cout << "Directory not found " << folder << "\n";
                }
            }
            else if(task.substr(0,5) == "read "){
                // cout << directory << "\n";
                string paths = directory/task.substr(5);
                // string paths = "/Users/benfrost/Desktop/example.txt";
                cout << paths << "\n";
                paths.erase(remove_if(paths.begin(), paths.end(), ::isspace), paths.end());
                ifstream file(paths);
                cout << paths << "\n";
                
                if(file.is_open()){
                    string line;
                    while (getline(file, line)){
                        cout << line << "\n";
                    }
                    file.close();
                }
                else{
                    cout << "couldnt open the file";
                }
            }
            
            
        }
        cout << ">> ";
        
    }

else if (os == "Windows"){
        string directory = desktop();
        if(fs::exists(directory) && fs::is_directory(directory)){

        vector<fs::path> files;
        int index = 0;
        for(const auto& i : fs::directory_iterator(directory)){
            if (fs::is_regular_file(i)){
                cout << "index " << index << " has file " << i.path().filename() << "\n";
                files.push_back(i);
                index ++;
                

            
            if(files.empty()){
                cout << "nothing in these files\n";
                return;
            }
        }
            
            
        }
        int indexing;
        cout << "what file do you want to look at ?\n";
        cin >> indexing;
        if (indexing >= 0 && indexing < files.size()){
            ifstream file_choice(files[indexing]);
            int lineCount = 0;
            if (file_choice.is_open()){
                string line;
                while(std::getline(file_choice, line)){
                    cout << "The Line Number Is " << lineCount << " " << line << "\n";
                    lineCount ++;
                }

            }

                                
        }
        
    }
    }

}


