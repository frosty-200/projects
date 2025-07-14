#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <cstring>
#include <chrono>
#include <thread>

using namespace std;
// class player to make any players 
class player{
  public:
  int health;
  float x, y;
// giving the hero stats that have to be filled
  player(int h, float xpos, float ypos){
    health = h;
    x = xpos;
    y = ypos;
  }
// this is to be able to see where the player is in relation to the zombies
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

// class to make a zombie
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


// this moves the zombies dependant on the hero player
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

// this makes more zombies based on how many are left
void make_z(){
  int limit = 2;
  zombie** horde = new zombie*[limit];
  for (int i = 0; i < limit; i++){
    horde[i] = new zombie(100, i * 14, 20);
  }
  
}

int main() {

    int limit = 5;
    int hlimit = 1;
  // this is the point to the pointer of zombies, this is bascially
  // an array of zombies but the array is empty until they've been made
    zombie** horde = new zombie*[limit];
    player** hero = new player*[1];

  //this for loop creates the new zombies and adds them to horde
    for (int i = 0; i < limit; i++){
      horde[i] = new zombie(100, i * 10, 0);
    }
  // hero creation
    for (int i = 0; i < hlimit; i++){
      hero[0] = new player(100, 40, 40);
    }
  //keeps track of alive and beaten zombies
    int actice_Z = limit;
    int dead_z = 0;
  // iterates over each move, this is set to 1000
    for (int t = 0; t < 1000; t++){
      // iterate through the zonmbies and see which ones are dead to remove
      for (int i = 0; i < actice_Z; i++){
        if (horde[i]->health <= 0){
          delete horde[i];
          // shift the zombies in the array down so there isnt any memory issues
          for (int j = i; j < actice_Z - 1; j++){
            horde[j] = horde[j + 1]; 
          }
          horde[actice_Z -1] = nullptr;
          actice_Z --;
          dead_z ++;

          // makes new zombies if the limit amount is less than it should be
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
    
    
