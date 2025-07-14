#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <cstring>
#include <chrono>
#include <thread>

using namespace std;

class player{
  public:
  int health;
  float x, y;

  player(int h, float xpos, float ypos){
    health = h;
    x = xpos;
    y = ypos;
  }

  void printhero(){
  cout << "hero is at " << x << " and " << y <<"\n";
  }

  int attacking(){
    int one = 10;
    int two = 20;
    int three = 30;

    int atk;
    cout << "what attack do you want to use ?\n10 | 20 | 30\n";
    cin >> atk;
    if (atk == 10){
      return 10;
    }
    else if (atk == 20){
      return 20;
    }
    else if (atk == 30){
      return 30;
    }
    return 0;
  }
  
};


class zombie{
public:
  int health;
  float x, y;

  zombie(int h, float xpos, float ypos){
    health = h;
    x = xpos;
    y = ypos;
  }

    void attack(zombie* z, int id){
    cout << "zombie " << id << " attacking from " << x << " and " << y << " with health level of " << health << "\n";
  }

  void printPos(zombie* z, int id){
      cout << "zombie " << id << " is at x: " << x << " and y: " << y << "\n";
    }



  void move(player &player){
    float speed = 0.5;

    float dx = player.x - x;
    float yx = player.y - y;
    float distance = sqrt(dx * dx + yx * yx);

    if(distance > 0.1f){
      x += speed * dx / distance;
      y += speed * yx / distance;
    }
  }
};

// class dynamArray{
//   private:
//   int* data;
//   int size;
//   int capacity;

//   public:
//   dynamArray();
//   ~dynamArray();
//   void push(int value);
//   void pop();
//   void print();
//   int get(int index);
// };

//   dynamArray::dynamArray(){
//     capacity = 2;
//     size = 0;
//     data = new int[capacity];
//   }
//   dynamArray::~dynamArray(){
//     delete[] data;
//   }

//   void dynamArray::push(int value){
//     if (size == capacity){
//       int* newdata = new int[capacity * 2];
//       for(int i = 0; i < size; i ++){
//         newdata[i] = data[i];
//       }
    
//     delete[] data;
//     data = newdata;
//     capacity *= 2;
//     }
//     data[size] = value;
//     ++size;
//   }

//   void dynamArray::pop(){
//     if (size > 0){
//       -- size;
//     }
//     else{
//       cout << "the array is already empty";
//     }
//   }

//   int dynamArray::get(int index){
//     if (index >= 0 && index < size){
//       return data[index];
//     }
//     else {
//       cout << "data out of bounds";
//       return -1;
//     }
//   }

//   void dynamArray::print(){
//     for (int i = 0; i < size; i++){
//       cout << data[i] << "\n";
//     }
    
//   }


void make_z(){
  int limit = 2;
  zombie** horde = new zombie*[limit];
  for (int i = 0; i < limit; i++){
    horde[i] = new zombie(100, i * 14, 20);
  }
  
}

int main() {
    // dynamArray arr;

    // arr.push(10);
    // arr.push(20);
    // arr.push(30);  // triggers resize
    // arr.push(40);
    // arr.push(20);


    // arr.print(); // [ 10 20 30 40 ]

    // arr.pop();
    // arr.print(); // [ 10 20 30 ]

    // cout << "Element at index 1: " << arr.get(1) << endl;

// this is the salary one
    // int nums;
    // cout << "enter a number\n";
    // cin >> nums;
    // cin.ignore();

    // char** names = new char*[nums];
    // float* sal = new float[nums];

    // const int limit = 50;

    // for (int i = 0; i < nums; i++){
    //   names[i] = new char[limit];
    //   cout << "enter name of student : " << i + 1 << " :\n";
    //   cin.getline(names[i], limit);
    //   cout << "enter salary for " << names[i] << " :\n";
    //   cin >> sal[i];
    //   cin.ignore();
    // }

    // for (int i = 0; i < nums; i++){
    //   cout << names[i] << " gets paid " << sal[i] << endl;
    // }
    
    // delete[] names;
    // delete[] sal;




    // return 0;


    int limit = 5;
    int hlimit = 1;
    zombie** horde = new zombie*[limit];
    player** hero = new player*[1];

    for (int i = 0; i < limit; i++){
      horde[i] = new zombie(100, i * 10, 0);
    }
    for (int i = 0; i < hlimit; i++){
      hero[0] = new player(100, 40, 40);
    }
    int actice_Z = limit;
    int dead_z = 0;
    for (int t = 0; t < 1000; t++){    
      for (int i = 0; i < actice_Z; i++){
        if (horde[i]->health <= 0){
          delete horde[i];
          for (int j = i; j < actice_Z - 1; j++){
            horde[j] = horde[j + 1]; 
          }
          horde[actice_Z -1] = nullptr;
          actice_Z --;
          dead_z ++;

          
            if(actice_Z < limit){
              horde[actice_Z] = new zombie(90, rand() %50, rand()%50);
              cout << "a new zombie has spawned in....\n";
              actice_Z ++;
            }
            dead_z = 0;
          
          i--;
          continue;
        }
        
        horde[i]->attack(horde[i], i);
        horde[i]->move(*hero[0]);
        horde[i]->printPos(horde[i], i);
        hero[0]->printhero();
        // make_z();

        float dx = horde[i]->x - hero[0]->x;
        float yx = horde[i]->y - hero[0]->y;
        float distance = sqrt(dx * dx + yx * yx);

        if (distance < 0.5f){
          cout<< "the hero has been killed";
        }
        int atkDmg = hero[0]->attacking();

        if (atkDmg == 10 || atkDmg == 20 || atkDmg == 30){
          horde[i]->health -= atkDmg;
          cout << "zombie " << i << " takes damage " << atkDmg << " current health is " << horde[i]->health << "\n";
          if (horde[i]->health <=0){
            cout << "ZOMBIE HAS BEEN BEATEN !!\n";
          }
        } 
     }
  }
    // for (int i = 0; i < limit; i++){
    //   delete horde[i];
    //   horde[i] = nullptr;
    // }
      delete hero[0];
      delete[] hero;
    
  }
    
    
