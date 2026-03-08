#include<iostream>
#include<vector>
#include "accounts.h"
#include"user.h"

using namespace std;

// this class sets the account balance and gets the account balance

void Account::displayBalance()
{
    cout << getaccounttype() << " £" << balance << endl;
}

//================================================================================================================================================================

string Account::getaccounttype() const
{
    if(account_type == SAVINGS) return "SAVINGS";
    if(account_type == CURRENT) return "CURRENT";
    if(account_type == STUDENT) return "STUDENT";
    return "unknown";
}



double Account::getbalance() const
{
    return balance;
}

AccountType Account::account(AccountType)
{
    return account_type;
}

void Account::deposit(float amount)
{
    balance += amount;
}

void Account::withdraw(float amount)
{
    balance -= amount;
}
