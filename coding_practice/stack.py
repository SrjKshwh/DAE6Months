# stack.py
# -----------------------------------------------------------------------------
# Your task: implement a simple Stack using a Python list.
#
# Functions to implement:
#   1. push(value)    -> put value on top of the stack
#   2. pop()          -> remove and return the top value, or None if empty
#   3. peek()         -> return the top value without removing it, or None if empty
#   4. is_empty()     -> return True if the stack has no items
#   5. size()         -> return how many items are in the stack
# -----------------------------------------------------------------------------

# The stack is stored in a list called "stack"
stack = []
stackIndex=-1
stackSize=0

# push(intValue) creates the newest index first and then adds the given intValue at the newest index 
def push(intValue):
    # add value to the top of the stack
    global stackIndex
    stackIndex += 1
    stack.append(intValue)
    print("Stack is having ",size()," elements which are as follows - ", stack)
    
# pop() deletes the newest element in the stack
def pop():
    global stackIndex
    if not is_empty():
        # stack.pop()           # pop() is predefined function which deletes last element of the list  ---- or ---
        deletingVal=stack[stackIndex]
        del stack[stackIndex]   # del deletes the value at stack[stackIndex] 
        stackIndex -=1
        print("After calling pop() stack is having ",size()," elements which are as follows - ",stack)
        return deletingVal
    else:
        print("Stack is EMPTY can't delete anything!")

# peek() returns last/newest value in the stack
def peek():
    global stackIndex
    if not is_empty():
        return stack[stackIndex]
    else:
        print("Stack is EMPTY can't delete anything!")
        return False


# is_empty() returns true if list is empty
def is_empty():
    if stackIndex == -1:
        return True
    else:
        return False

# size() returns the size(number of elements) of stack
def size():   
    stackSize=len(stack)        
    return stackSize



# ------  python program starts from here -------

'''(For this coding practice i am using Stack containing integer values) 
When the python program runs first time it checks for stackIndex variable initially stackIndex set to -1 as stack will be empty
and then ask user to enter any integer value for the stack
once the stack is not empty will ask for the options to operate '''

if stackIndex<0:
    print("Welcome to the world of STACK !!! \n Now you need to add some items in the empty stack\n")
    intValue=int(input("Enter an integer value for the stack - "))
    push(intValue)
    print("Stack is having ",size()," elements; what you want to do next ?")
    print("Press 1 to push (add new element to the stack)")
    print("Press 2 to pop (delete element to the stack)")
    print("Press 3 to peek (return the top value without removing it, or None if empty)")
    print("Press 4 for is_empty() (returns True if the stack has no items)")
    print("Press 5 to get the size of stack (returns how many items are in the stack)")
    print("Press 6 to quit (come out of the python program)")

enteredOption=1

if stackIndex>-1:
    while enteredOption>0 and enteredOption<6:
        enteredOption=int(input("Enter your option 1/2/3/4/5/6 - "))

        if enteredOption==1:
            intValue=int(input("Enter an integer value for the stack - "))
            push(intValue)
        
        if enteredOption==2:
            print("Before calling pop stack is having ",size()," elements which are as follows - ",stack)
            print("Deleted value is - ", pop())

        if enteredOption==3:
            peekedVal=peek()
            if peekedVal==False:
                print("Stack is empty, can't show any value")
            else:
                print("Newest element in the stack is - ",peekedVal)

        if enteredOption==4:
            print("is_empty() function returned - ",is_empty())

        if enteredOption==5:
            print("The size of stack is - ", size())




'''       Output -------------

c:/Users/saroj/OneDrive/Desktop/course/FirstSetup/coding_practice/stack.py

Welcome to the world of STACK !!! 
 Now you need to add some items in the empty stack

Enter an integer value for the stack - 125
Stack is having  1  elements which are as follows -  [125]
Stack is having  1  elements; what you want to do next ?
Press 1 to push (add new element to the stack)
Press 2 to pop (delete element to the stack)
Press 3 to peek (return the top value without removing it, or None if empty)
Press 4 for is_empty() (returns True if the stack has no items)
Press 5 to get the size of stack (returns how many items are in the stack)
Press 6 to quit (come out of the python program)
Enter your option 1/2/3/4/5/6 - 1
Enter an integer value for the stack - 89
Stack is having  2  elements which are as follows -  [125, 89]
Enter your option 1/2/3/4/5/6 - 1
Enter an integer value for the stack - 784
Stack is having  3  elements which are as follows -  [125, 89, 784]
Enter your option 1/2/3/4/5/6 - 1
Enter an integer value for the stack - 2463
Stack is having  4  elements which are as follows -  [125, 89, 784, 2463]
Enter your option 1/2/3/4/5/6 - 1
Enter an integer value for the stack - 7836
Stack is having  5  elements which are as follows -  [125, 89, 784, 2463, 7836]
Enter your option 1/2/3/4/5/6 - 5
The size of stack is -  5
Enter your option 1/2/3/4/5/6 - 4
is_empty() function returned -  False
Enter your option 1/2/3/4/5/6 - 3
stackIndex 4
5
Newest element in the stack is -  7836
Enter your option 1/2/3/4/5/6 - 2
Before calling pop stack is having  5  elements which are as follows -  [125, 89, 784, 2463, 7836]
After calling pop() stack is having  4  elements which are as follows -  [125, 89, 784, 2463]
Enter your option 1/2/3/4/5/6 - 2
Before calling pop stack is having  4  elements which are as follows -  [125, 89, 784, 2463]
After calling pop() stack is having  3  elements which are as follows -  [125, 89, 784]
Enter your option 1/2/3/4/5/6 - 2
Before calling pop stack is having  3  elements which are as follows -  [125, 89, 784]
After calling pop() stack is having  2  elements which are as follows -  [125, 89]
Enter your option 1/2/3/4/5/6 - 4
is_empty() function returned -  False
Enter your option 1/2/3/4/5/6 - 2
Before calling pop stack is having  2  elements which are as follows -  [125, 89]
After calling pop() stack is having  1  elements which are as follows -  [125]
Enter your option 1/2/3/4/5/6 - 4
is_empty() function returned -  False
Enter your option 1/2/3/4/5/6 - 2
Before calling pop stack is having  1  elements which are as follows -  [125]
After calling pop() stack is having  0  elements which are as follows -  []
Enter your option 1/2/3/4/5/6 - 4
is_empty() function returned -  True
Enter your option 1/2/3/4/5/6 - 1
Enter an integer value for the stack - 45454
Stack is having  1  elements which are as follows -  [45454]
Enter your option 1/2/3/4/5/6 - 1
Enter an integer value for the stack - 78
Stack is having  2  elements which are as follows -  [45454, 78]
Enter your option 1/2/3/4/5/6 - 2
Before calling pop stack is having  2  elements which are as follows -  [45454, 78]
After calling pop() stack is having  1  elements which are as follows -  [45454]
Enter your option 1/2/3/4/5/6 - 4
is_empty() function returned -  False
Enter your option 1/2/3/4/5/6 - 2
Before calling pop stack is having  1  elements which are as follows -  [45454]
After calling pop() stack is having  0  elements which are as follows -  []
Enter your option 1/2/3/4/5/6 - 4
is_empty() function returned -  True
Enter your option 1/2/3/4/5/6 - 2
Before calling pop stack is having  0  elements which are as follows -  []
Stack is EMPTY can't delete anything!
Enter your option 1/2/3/4/5/6 - 1
Enter an integer value for the stack - 224
Stack is having  1  elements which are as follows -  [224]
Enter your option 1/2/3/4/5/6 -6



'''

