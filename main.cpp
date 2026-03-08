#include<iostream>
#include<limits>
#include<string>
#include<cstring>
#include<vector>
#include"accounts.h"
#include"user.h"
#include <algorithm>
#include <cctype>



std::string caps(std::string account_type){
    std::transform(account_type.begin(), account_type.end(), account_type.begin(), 
    [](unsigned char c){return std::toupper(c);});
    return account_type;
}

//================================================================================================================================================================

int main()
{   vector<User> users;
    while(true){
    

    int choice;   
    std::cout << "WHART WOULD YOU LIKE TO DO ? \n============================\nCREATE ACCOUNT | 1 \nADD TO ACCOUNT | 2\nSHOW ACCOUNT   | 3 \nWITHDRAW       | 4\nEXIT           | 5\n" << std::endl;
    cin >> choice;
    if(choice == 1){
        string name;
        cout << "ENTER USERNAME: " << endl;
        cin >> name;
        User newUser(name);
        users.push_back(newUser);
    }
   
    if(choice == 2){
        // std::cout << "you entered number 2" << std::endl;
        std::string name;
        cout << "ACCOUNT NAME: " << std::endl;
        cin >> name;
        auto it = std::find_if(users.begin(), users.end(), 
        [&] (User &u){
            return u.getUser() == name;});
        if(it == users.end())
        {
            std::cout << "COULDN'T FIND THE USERS" << std::endl;
        }
        else{
                
            int account_type;
            std::cout << "ENTER THE TYPE OF ACCOUNT | SAVINGS 1 | CURRENT 2 | STUDENT 3\n";
            
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            cin >> account_type;

            double amount;
            std::cout << "AMOUNT FOR DEPOSIT\n";
            cin >> amount;

            if(account_type == 1)
            {
                it->addaccount(Account(SAVINGS, amount)); //name(SAVINGS, amount);
                std::cout << "UPDATED SAVINGS WITH £" << amount << std::endl;
            }
            if(account_type == 2)
            {
                it->addaccount(Account(CURRENT, amount));
                // Account name(CURRENT, amount);
                std::cout << "UPDATED CURRENT WITH £" << amount << std::endl;
                
            }
            if(account_type == 3)
            {
                it->addaccount(Account(STUDENT, amount));
            }
            // std::cout << account_type << std::std::endl;
            
        }
        }
        if (choice == 3)
        {
            std::string name;
            std::cout << "NAME OF ACCOUNT: " << endl;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            getline(cin, name);

            auto it = std::find_if(users.begin(), users.end(), 
            [&] (User &u)
            {return u.getUser() == name;});
            
            if(it == users.end())
            {
                std::cout << "NO USER FOUND" << endl;
            }
            else
            {
                std::cout << endl;
                it->displayAccounts();
                std::cout << endl;
            }
        }
        if(choice == 4)
        {
            std::cout << "ENTER NAME OF ACCOUNT" << endl;
            std::string name;
            cin >> name;

            auto find_name = find_if(users.begin(), users.end(), [&] (User &u){
                return u.getUser() == name;});

            if(find_name == users.end())
            {
                std::cout << "NO USERS FOUND" << endl;
            }
            else
            {
                int account_type;
                std::cout << "ENTER THE TYPE OF ACCOUNT | SAVINGS 1 | CURRENT 2 | STUDENT 3\n";
                
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                cin >> account_type;

                double amount;
                std::cout << "AMOUNT FOR WITHDRAWL\n";
                cin >> amount;
                if(account_type == 1)
                {
                    find_name->remove(Account(CURRENT, amount));
                    std::cout << "TAKEN " << amount << " FROM THE ACCOUNT CURRENT" << endl;
                }
                if (account_type == 2)
                {
                    find_name->remove(Account(SAVINGS, amount));
                    std::cout << "TAKEN THE AMOUNT " << amount << "FROM THE ACCOUNT SAVINGS" << endl;
                }
                if (account_type == 3)
                {
                    find_name->remove(Account(STUDENT, amount));
                    std::cout << "TAKEN THE AMOUNT " << amount << "FROM THE ACCOUNT STUDENT" << endl;
                    std::cout << "NEW BALANCE IS "; find_name->displayAccounts();
                }
                
                

            }

        }
        if(choice == 5)
        {
            break;
        }
    }
}


// User ben("ben");
// Account bensSavings(SAVINGS, 7000);
// Account bensCurrent(CURRENT, 10000);
// Account bensStudent(STUDENT, 300);

// ben.addaccount(bensSavings);
// ben.addaccount(bensCurrent);
// ben.addaccount(bensStudent);

// ben.displayAccounts();


