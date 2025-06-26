import tkinter as tk
from tkinter import font
import random
import string

#----------------------------------------LOGIC ON GUI INITIAL LOADING----------------------------------------------------
# getting random words from text file
matrixSize=20
rows = []
grid_cells = [[random.choice(string.ascii_uppercase) for _ in range(matrixSize)] for _ in range(matrixSize)]
coordinates = []
rndWordList=[]

with open("C:/Users/saroj/OneDrive/Desktop/course/FirstSetup/python_1/listTextFile.txt", "r") as file:
    allText = file.read()
    words = list(map(str, allText.split()))
    for i in range(7):
        randomWord=random.choice(words)
        if randomWord in rndWordList:
            randomWord=random.choice(words)
        else:
            rndWordList.append(randomWord)
print(rndWordList)


#----------------------------------------DEFINING FUNCTIONS---------------------------------------------------- 

# add user given words to random above list
def addToList():
    print("1--: %s\n2--: %s\n3--: %s" % (e1.get(), e2.get(), e3.get()))
    rndWordList.append(e1.get().upper())
    rndWordList.append(e2.get().upper())
    rndWordList.append(e3.get().upper())
    print(rndWordList)
    listbox=tk.Listbox(right_frame)
    for item in rndWordList:
        listbox.insert(tk.END, item)
    listbox.grid(row=7, column=1, padx=10, pady=10)
    #e1.grid_forget()
    #e2.grid_forget()  
    #e3.grid_forget()
    button2.grid_forget()

    for wrds in rndWordList:
        randomCoordinate=random.choice(coordinates)
        #print(randomCoordinate)
        x,y=map(int, randomCoordinate.split(","))
        #print(x,y)
        if x>matrixSize/2 and y>matrixSize/2: #8 8    
            print(x,y,"down right")
            setWordFromDownRight(x,y,wrds)
        if x>matrixSize/2 and y<matrixSize/2: # 9 4
            print(x,y,"down left")
            setWordFromDownLeft(x,y,wrds)
        if x<matrixSize/2 and y<matrixSize/2:   # 
            print(x,y,"up left")
            setWordFromUpLeft(x,y,wrds)
        if x<matrixSize/2 and y>matrixSize/2:
            print(x,y,"up right")
            setWordFromUpRight(x,y,wrds)

    for r in range(matrixSize):
        for c in range(matrixSize):
            tk.Label(left_frame, text=grid_cells[r][c], padx=6, pady=4, bg='lightblue').grid(row=r, column=c)
       


def setWordFromDownRight(x,y,wrd):
    length=len(wrd)
    print(length)
    chars=list(wrd)
    print("----",x,y,wrd)
    for i in range(length):
        grid_cells[x][y]=chars[i]
        print("---",x,y,chars[i])
        cordi=f"{x},{y}"
        if cordi in coordinates:
            coordinates.remove(cordi)
        x-=1
        y-=1
    

def setWordFromDownLeft(x,y,wrd):
    length=len(wrd)
    print(length)
    chars=list(wrd)
    for i in range(length):
        grid_cells[x][y]=chars[i]
        print("----*******-----",x,y,chars[i])
        cordi=f"{x},{y}"
        if cordi in coordinates:
            coordinates.remove(cordi)
        x-=1
        y+=1


def setWordFromUpRight(x,y,wrd):
    length=len(wrd)
    print(length)
    chars=list(wrd)
    print("---------",x,y,wrd)
    for i in range(length):
        grid_cells[x][y]=chars[i]
        print("---------",x,y,chars[i])
        cordi=f"{x},{y}"
        if cordi in coordinates:
            coordinates.remove(cordi)
        x+=1
        y-=1
           


def setWordFromUpLeft(x,y,wrd):
    length=len(wrd)
    print(length)
    chars=list(wrd)
    print("--------",x,y,wrd)
    for i in range(length):
        grid_cells[x][y]=chars[i]
        print("-----///////----",x,y,chars[i])
        cordi=f"{x},{y}"
        if cordi in coordinates:
            coordinates.remove(cordi)
        x+=1
        y+=1
           


#----------------------------------------CREATING GUI---------------------------------------------------- 
# creating main tkinter interface and dividing into left and right panel
master = tk.Tk()
master.title("Wordsearch (falling into words)")

left_frame = tk.Frame(master, width=400, height=400, bg='lightblue')
left_frame.grid(row=0, column=0, padx=20, pady=20)
right_frame = tk.Frame(master, width=400, height=400, bg='lightgray')
right_frame.grid(row=0, column=1, padx=20, pady=20)


default_font = font.Font(family="Arial", size=12)
# Set default font for Label, Entry and Button widgets
left_frame.option_add("*Label.Font", default_font)
right_frame.option_add("*Label.Font", default_font)
right_frame.option_add("*Button.Font", default_font)
right_frame.option_add("*Entry.Font", default_font)
right_frame.option_add("*Listbox.Font", default_font)

#--------------------------LEFT PANEL CONTENT STARTS------------------------------------------- 

for r in range(matrixSize):
    for c in range(matrixSize):
        # word search logic
        random_char=random.choice(string.ascii_uppercase)
        #print(random_char)
        tk.Label(left_frame, text=random_char, padx=6, pady=4, bg='lightblue').grid(row=r, column=c)
        rows.append(random_char)
        cordi=f"{r},{c}"
        coordinates.append(cordi)
    #print(rows)
    #print("\n")
grid_cells.append(rows)
#print(grid_cells)
#print(coordinates)



#--------------------------LEFT PANEL CONTENT ENDS--------------------------------------------- 



#--------------------------RIGHT PANEL CONTENT STARTS------------------------------------------- 
# creating labels for text box and adding to the grid
tk.Label(right_frame, text="1st word", bg='lightgray').grid(row=1)
tk.Label(right_frame, text="2nd word", bg='lightgray').grid(row=2)
tk.Label(right_frame, text="3rd word", bg='lightgray').grid(row=3)

# creating input boxes
e1 = tk.Entry(right_frame)
e2 = tk.Entry(right_frame)
e3 = tk.Entry(right_frame)

# adding input boxes to the grid
e1.grid(row=1, column=1)
e2.grid(row=2, column=1)
e3.grid(row=3, column=1)

# creating buttons and adding to the grid
button1=tk.Button(right_frame, text='Quit', command=master.quit)
button1.grid(row=6, column=1, padx=5, pady=5, sticky='ew')

button2=tk.Button(right_frame, text='Add to list', command=addToList)
button2.grid(row=5, column=1, padx=5, pady=5, sticky='ew')

#--------------------------RIGHT PANEL CONTENT ENDS------------------------------------------- 


tk.mainloop()