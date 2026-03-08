#include<vector>
#include<iostream>
#include<string>
#include"user.h"
#include"accounts.h"

using namespace std;

    string User::getUser()
    {
        return string(username);
    }
//================================================================================================================================================================
    void User::addUser(const string &user)
    {
        username = user;
    }
//================================================================================================================================================================
    void User::addaccount(const Account &acc)
    {
        for(Account &exist : account)
        {
            if(exist.getaccounttype() == acc.getaccounttype())
            {
                exist.deposit(acc.getbalance());
                return;
            }
        }
        account.push_back(acc);
}
//================================================================================================================================================================

void User::remove(const Account &acc)
{
    for(Account &exist : account)
    {
        if(exist.getaccounttype() == acc.getaccounttype())
        {
            exist.withdraw(acc.getbalance());
            return;
        }
    }
    account.push_back(acc);
}

//================================================================================================================================================================

void User::displayAccounts()
    {
        for(Account &acc : account){
            acc.displayBalance();
        }
        
    }