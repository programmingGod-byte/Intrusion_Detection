#include <iostream>
#include <string>
#include "FastVector.h"

struct Order {
    int id;
    std::string symbol;
    double price;

    Order(int i, std::string s, double p) : id(i), symbol(std::move(s)), price(p) {}
};

int main() {
    std::cout << "Testing Aethon SmallVector / FastVector...\n";

    aethon::SmallVector<Order, 4> vec;

    std::cout << "Initial size: " << vec.size() << ", capacity: " << vec.capacity() << "\n";

    // Insert 4 items (Inline Stack Mode)
    vec.emplace_back(1, "AAPL", 150.25);
    vec.emplace_back(2, "GOOG", 2800.50);
    vec.emplace_back(3, "MSFT", 300.75);
    vec.emplace_back(4, "AMZN", 3400.10);

    std::cout << "After 4 pushes (Inline Mode): size = " << vec.size() << ", capacity = " << vec.capacity() << "\n";

    // Insert 5th item (Triggers Heap Growth to capacity 8)
    vec.emplace_back(5, "TSLA", 700.00);

    std::cout << "After 5th push (Heap Mode): size = " << vec.size() << ", capacity = " << vec.capacity() << "\n";

    for (size_t i = 0; i < vec.size(); ++i) {
        std::cout << "Order [" << vec[i].id << "]: " << vec[i].symbol << " @ $" << vec[i].price << "\n";
    }

    std::cout << "\nAll SmallVector tests passed successfully!\n";
    return 0;
}
