#ifndef ACCOUNT_H
#define ACCOUNT_H

#include <vector>

using namespace std;

enum AccountType {
    SAVINGS,
    CURRENT,
    STUDENT
};

class Account{
    private:

    double balance;
    AccountType account_type;
    
    public:

    Account(AccountType type, float amount) : balance(amount), account_type{type}{};
    void displayBalance();

    string getaccounttype() const;
    double getbalance() const;
    AccountType account(AccountType);
    void deposit(float amount);
    void withdraw(float amount);
};

#endif