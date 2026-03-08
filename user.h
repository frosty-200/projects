#ifndef USER_H
#define USER_H

#include <iostream>
#include <vector>
#include <string>
#include "accounts.h"

class User{
private:
    std::string username;
    vector<Account> account;
    
public:
    User(const std::string &name) : username(name){}

    std::string getUser();
    void addUser(const std::string &user);
    void displayAccounts();
    void remove(const Account &acc);
    void addaccount(const Account &acc);
};

#endif