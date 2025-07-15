#include <iostream>
#include <stdlib.h>
#include <ctime>
#include <vector>

using namespace std;
void display_board(char board[3][3]);
void init_board(char board[3][3]);
bool check_win(char board[3][3], char player1, char player2);
bool make_move(char board[3][3], char move, char current_player);

const char player1 = 'X';
const char player2 = 'O';

int main(){

    char board[3][3];
    init_board(board);
    char current_player = player1;
    while (true){
    
    display_board(board);
    char move;
    cout << "choose a spot to hit" << "\n";
    cin >> move;
    
    if(make_move(board, move, current_player)){
        if (check_win(board, player1, player2)){
            display_board(board);
            break;
        }
    } current_player = (current_player == player1) ? player2 : player1;
    }
    

    

//     std::vector<std::vector<int>> grid(3, vector<int>(3));
//     int count = 1;

//     for(int i=0; i < 3; i++){
//         for(int j = 0; j < 3; j++){
//             grid[i][j] = count++;
//         }
//     }

//     for (const auto& row : grid){{
//         for (int value : row){
//             cout << value << "\t";
//         }
//     } std::cout << std::endl;
//     }
//     input(std::vector<std::vector <int>> grid(3, vector<int>(3));

//     return 0;
// }


// void input(char board[3][3]){
//     cout << board[0][2];


}

void init_board(char board[3][3]){
    char count = '1';
    // cout << typeid(count).name();
    for(int i = 0; i < 3; i++){
        // cout << typeid(board).name();
        for (int j = 0; j < 3; j++){
            board[i][j] = count++;
        }
        // cout << endl;
    }
}

void display_board(char board[3][3]){
    for(int i = 0; i < 3; i++){
        cout << " ";
        for(int j = 0; j < 3; j++){
            cout << board[i][j];
            if(j < 2) cout << " | ";
        }    
        cout << endl;
        if(i < 2) cout << "---+---+---" << endl;
        
    }
}


bool make_move(char board[3][3], char num, char currentPlayer) {
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            if (board[i][j] == num) {
                board[i][j] = currentPlayer;
                return true;
            }
        }
    }
    cout << "Cannot play there\n";
    return false;
}


    // if (row < 3 && row >= 0 && col < 3 && col >= 0){
    //     if(board[row][col] != 'X' || 'O'){
    //         board[row][col] = player;
    //         return true;
    //     }
    //     else{
    //         cout << "cell already taken";
    //     }
       
    // }
    // else{
    //     cout << "invalid move";
    // }
    // return false;
    
    


bool check_win(char board[3][3], char player1, char player2){
    for(int i = 0; i < 3; i++){
        if ((board[i][0] == player1 && board[i][1] == player1 && board [i][2] == player1) || 
            (board[0][i] ==player1 && board[1][i] == player1 && board[2][i] == player1)){
            cout << "player 1 wins!!\n";
            return true; 
    }
        
    if((board[i][0] == player2 && board[i][1] == player2 && board[i][2] == player2)||
        (board[0][i] == player2 && board[1][i] == player2 && board[2][i] == player2)){
        return true;
        }}
    
    
    if ((board[0][0] == player1 && board[1][1] == player1 && board[2][2] == player1) ||
        (board[0][2] == player1 && board[1][1] == player1 && board[2][0] == player1)){
        cout << "player 1 wins!!";
        return true;}



    if ((board[0][0] == player2 && board[1][1] == player2 && board[2][2] == player2)||
        (board[0][2] == player2 && board[1][1] == player2 && board[2][0] == player2)){
        return true;

} return false;}

