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
        del stack[stackIndex]   # del deletes the value at stack[stackIndex] 
        stackIndex -=1
        print("After calling pop() stack is having ",size()," elements which are as follows - ",stack)
    else:
        print("Stack is EMPTY can't delete anything!")

# peek() returns last/newest value in the stack
def peek():
    global stackIndex
    return stack[stackIndex]

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
            pop()

        if enteredOption==3:
            print("Newest element in the stack is - ", peek())

        if enteredOption==4:
            print("is_empty() function returned - ",is_empty())

        if enteredOption==5:
            print("The size of stack is - ", size())
