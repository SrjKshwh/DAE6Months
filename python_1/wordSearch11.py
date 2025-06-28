import tkinter as tk
from tkinter import font
import random
import string

#----------------------------------------LOGIC ON GUI INITIAL LOADING----------------------------------------------------

# Global variables
matrixSize=20
rows = []
grid_cells = [[random.choice(string.ascii_uppercase) for _ in range(matrixSize)] for _ in range(matrixSize)]
coordinates = []
rndWordList=[]
usedCoordinates=[]
tempCoord=[]
wordsAlloted=[]

# getting random words from text file
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

    rndWordList.sort(key=len, reverse=True)
    print(rndWordList)
    for wrds in rndWordList:
        allotWordsToGrid(wrds)
    
    for checkWord in rndWordList:
        if checkWord not in wordsAlloted:
            allotWordsToGrid(checkWord)   

    for r in range(matrixSize):
        for c in range(matrixSize):
            tk.Label(left_frame, text=grid_cells[r][c], padx=6, pady=4, bg='lightblue').grid(row=r, column=c)


def allotWordsToGrid(wrds):
    
    randomCoordinate=random.choice(coordinates)
    #print(randomCoordinate)
    x,y=map(int, randomCoordinate.split(","))
    leng=len(wrds)

    if leng<matrixSize and leng>matrixSize-4:
        print(x,y,"down right")
        setWordFromDownRight(x,y,wrds,leng)
    if x>matrixSize/2 and y>matrixSize/2: #8 8    
        print(x,y,"down right")
        setWordFromDownRight(x,y,wrds,leng)
    if x>matrixSize/2 and y<matrixSize/2: # 9 4
        print(x,y,"down left")
        setWordFromDownLeft(x,y,wrds,leng)
    if x<matrixSize/2 and y<matrixSize/2:   # 
        print(x,y,"up left")
        setWordFromUpLeft(x,y,wrds,leng)
    if x<matrixSize/2 and y>matrixSize/2:
        print(x,y,"up right")
        setWordFromUpRight(x,y,wrds,leng)


def setWordFromDownRight(x,y,wrd,leng):
    chars=list(wrd)
    for i in range(leng):
        tempX=x-i
        tempY=y-i
        print("----------",tempX,tempY,chars[i])
        cordi=f"{tempX},{tempY}"
        if cordi in usedCoordinates or tempX<0 or tempX>matrixSize-1 or tempY<0 or tempY>matrixSize-1:
            randomCoordinate=random.choice(coordinates)
            #print(randomCoordinate)
            newX,newY=map(int, randomCoordinate.split(","))
            return setWordFromDownRight(newX,newY,wrd,leng)
        grid_cells[tempX][tempY]=chars[i]
        usedCoordinates.append(cordi)
    print("setWordFromDownRight done--",wrd)
    wordsAlloted.append(wrd)


def setWordFromDownLeft(x,y,wrd,leng):
    chars=list(wrd)
    for i in range(leng):
        tempX=x-i
        tempY=y+i
        print("-- * ///----",tempX,tempY,chars[i])
        cordi=f"{tempX},{tempY}"
        if cordi in usedCoordinates or tempX<0 or tempX>matrixSize-1 or tempY<0 or tempY>matrixSize-1:
            randomCoordinate=random.choice(coordinates)
            #print(randomCoordinate)
            newX,newY=map(int, randomCoordinate.split(","))
            return setWordFromDownLeft(newX,newY,wrd,leng)
        grid_cells[tempX][tempY]=chars[i]
        usedCoordinates.append(cordi)
    print("setWordFromDownLeft done--",wrd)
    wordsAlloted.append(wrd)


def setWordFromUpRight(x,y,wrd,leng):
    chars=list(wrd)
    for i in range(leng):
        tempX=x+i
        tempY=y-i
        print("-----/// * ---",tempX,tempY,chars[i])
        cordi=f"{tempX},{tempY}"
        if cordi in usedCoordinates or tempX<0 or tempX>matrixSize-1 or tempY<0 or tempY>matrixSize-1:
            randomCoordinate=random.choice(coordinates)
            #print(randomCoordinate)
            newX,newY=map(int, randomCoordinate.split(","))
            return setWordFromUpRight(newX,newY,wrd,leng)
        grid_cells[tempX][tempY]=chars[i]
        usedCoordinates.append(cordi)
    print("setWordFromUpRight done--",wrd)
    wordsAlloted.append(wrd)
           

def setWordFromUpLeft(x,y,wrd,leng):
    chars=list(wrd)
    for i in range(leng):
        tempX=x+i
        tempY=y+i
        print("-------------------",tempX,tempY,chars[i])
        cordi=f"{tempX},{tempY}"
        if cordi in usedCoordinates or tempX<0 or tempX>matrixSize-1 or tempY<0 or tempY>matrixSize-1:
            randomCoordinate=random.choice(coordinates)
            #print(randomCoordinate)
            newX,newY=map(int, randomCoordinate.split(","))
            return setWordFromUpLeft(newX,newY,wrd,leng)
        grid_cells[tempX][tempY]=chars[i]
        usedCoordinates.append(cordi)
    print("setWordFromUpLeft done--",wrd)
    wordsAlloted.append(wrd)
           

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