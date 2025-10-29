def print_items(list1):
    for i in list1:
        print("\n" , i) 

list1=[34, 35, 67, 4, 7, 56]
print_items(list1)

#######################################

def show_total(numbers): 
    total = 0 
    for number in numbers:
        total += number 
    print("Total:", total) 

show_total([1, 2, 3]) 