#include <iostream>

using namespace std;

class counter
{
public:
    counter() { v=0; }
    counter operator ++();
    counter operator ++(int);
    counter& operator =(counter &a);
    //friend complex operator +(const complex &c1, const complex &c2);
    void print() { cout << v << endl; }

private:
    unsigned v;
};

counter counter::operator ++()
{
    v++;
    return *this;
}

counter counter::operator ++(int)
{
    counter t;
    t.v = v++;
    return t;
}

counter& counter::operator =(counter &a)
{
    this->v = a.v;
    return *this;
}

int main()
{
    int i = 0;

    counter c;
    for(i=0; i<8; i++)
        c++;
    c.print();

    counter d;
    d.print();
    /*
    for(i=0; i<8; i++)
        ++d;
    d.print();
    */
    d = c;
    d.print();

    return 0;
} 
