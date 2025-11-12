def print_even_or_odd(numbers):
    for n in numbers:
        if n % 2 == 0:  # syntax bug
            print(n, "is even")
        else:
            print(n, "is odd")
print_even_or_odd([1, 2, 3])