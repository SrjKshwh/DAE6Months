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
coordiForLongWord=[]

# getting random words from text file
def getWordsFromFile():
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

#----- setting some coordinates for long words
for i in range(matrixSize-3, matrixSize):
    for j in range(matrixSize-3, matrixSize):
        coord=f"{i},{j}"
        coordiForLongWord.append(coord)
print(coordiForLongWord)

getWordsFromFile()

if len(rndWordList)!=7:
    getWordsFromFile()




#----------------------------------------DEFINING FUNCTIONS---------------------------------------------------- 





# add user given words to random above list on button click
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

   #---------------- alloting words in the grid---------------------------------
    rndWordList.sort(key=len, reverse=True)  #---sorting the list in descending order of word size
    print(rndWordList)
    for wrds in rndWordList:
        allotWordsToGrid(wrds)

   #----------------checking whether all the words are alloted in the grid or not; if not then allot it----------------   
    for checkWord in rndWordList:
        if checkWord not in wordsAlloted:
            allotWordsToGrid(checkWord)   

   #----------print grid with the all ten words--------------------------
    for r in range(matrixSize):
        for c in range(matrixSize):
            tk.Label(left_frame, text=grid_cells[r][c], padx=6, pady=4, bg='lightblue').grid(row=r, column=c)


#------ function to allot word-------------------------------
def allotWordsToGrid(wrds):
    leng=len(wrds)
    if leng>=matrixSize-2:
        print(wrds,leng," is too big for the grid")
        rndWordList.remove(wrds)
        return #exit the function safely
    if leng>matrixSize-6:
        allotLogWordToGrid(wrds,leng)
        return

    randomCoordinate=random.choice(coordinates)
    x,y=map(int, randomCoordinate.split(","))
    if x>matrixSize/2 and y>matrixSize/2:  
        print(x,y,"down right")
        setWordFromDownRight(x,y,wrds,leng)
        return    
    if x>matrixSize/2 and y<matrixSize/2:
        print(x,y,"down left")
        setWordFromDownLeft(x,y,wrds,leng)
        return    
    if x<matrixSize/2 and y<matrixSize/2:  
        print(x,y,"up left")
        setWordFromUpLeft(x,y,wrds,leng)
        return    
    if x<matrixSize/2 and y>matrixSize/2:
        print(x,y,"up right")
        setWordFromUpRight(x,y,wrds,leng)
        return


def allotLogWordToGrid(wrd,leng):     
    randomCoordinate=random.choice(coordiForLongWord)
    print(randomCoordinate)
    x,y=map(int, randomCoordinate.split(","))
    print(x,y,"long word checking--------------leng-",leng)  
    chars=list(wrd)
    for i in range(leng):
        tempX=x-i
        tempY=y-i
        print("---long----",tempX,tempY,chars[i])
        cordi=f"{tempX},{tempY}"
        if cordi in usedCoordinates or tempX<0 or tempX>matrixSize-1 or tempY<0 or tempY>matrixSize-1:
            randomCoordinate=random.choice(coordiForLongWord)
            #print(randomCoordinate)
            newX,newY=map(int, randomCoordinate.split(","))
            return allotLogWordToGrid(wrd,leng)
        grid_cells[tempX][tempY]=chars[i]
        usedCoordinates.append(cordi)
    print("allotLogWordToGrid done--",wrd)
    wordsAlloted.append(wrd)


def setWordFromDownRight(x,y,wrd,leng):
    chars=list(wrd)
    for i in range(leng):
        tempX=x-i
        tempY=y-i
        print("--------",tempX,tempY,chars[i])
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
        print("-++++++++---",tempX,tempY,chars[i])
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
        tk.Label(left_frame, text=grid_cells[r][c], padx=6, pady=4, bg='lightblue').grid(row=r, column=c)
        cordi=f"{r},{c}"
        coordinates.append(cordi)
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

tk.mainloop()import tkinter as tk
from tkinter import font
import random
import string
import tkinter.font as tkfont

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
coordiForLongWord=[]
seconds=0
timerRunning=False
makeStringFromLetters=""

#----------------------------------------DEFINING FUNCTIONS---------------------------------------------------- 

#--- Mouse enter event function
def highLightText(event):
    '''This is an event handling function: when mouse cursor is ON (mouse enter event) word search grid 
    this function make that text bold'''
    event.widget.config(font=boldFont)

#--- Mouse leave event function
def unHighlightText(event):
    '''This is an event handling function: when mouse cursor is leaving (mouse leave event) word search grid 
    this function make that text normal/unhighlighted'''
    event.widget.config(font=defaultFont)


#--- Mouse click event function for checking whether word is in tk.listbox or not
def changeLabelColor(event):
    global makeStringFromLetters, listbox

    orignalColor="lightblue"
    changedColor="lightgreen"
    label=event.widget
    currentColor=label.cget("bg")
    if currentColor == orignalColor:
        label.config(bg=changedColor)
    else:
        label.config(bg=orignalColor)

    curentLetter=label.cget("text")
    #print(curentLetter)
    makeStringFromLetters+=curentLetter
    print(makeStringFromLetters)
    #print(rndWordList)
    if makeStringFromLetters in rndWordList:
        index = listbox.get(0, tk.END).index(makeStringFromLetters) # Search the listbox for the word
        # Configure the item at the found index to have green foreground color
        listbox.itemconfig(index, {'fg': 'lightgreen'})


def updateTimer():
    global seconds, timerRunning
    if timerRunning:
        seconds +=1
        timerLabel.config(text=f"Time : {seconds} secs")
        right_frame.after(1000, updateTimer)

def startTime():
    global timerRunning
    if not timerRunning:
        timerRunning=True
        updateTimer()

def stopTime():
    global timerRunning
    timerRunning=False

def resetTime():
    global seconds, timerRunning
    timerRunning=False
    seconds=0
    timerLabel.config(text="Time 0 sec")

# getting random words from text file
def getWordsFromFile():
    with open("C:/Users/saroj/OneDrive/Desktop/course/FirstSetup/python_1/listTextFile.txt", "r") as file:
        allText = file.read()
        words = list(map(str, allText.split()))
        for count in range(7):
            randomWord=random.choice(words)
            if randomWord in rndWordList:
                randomWord=random.choice(words)
            else:
                rndWordList.append(randomWord)
    print(rndWordList)



# add user given words to random above list on button click
def addToList():
    global listbox
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
    buttonAddToList.grid_forget()

   #---------------- alloting words in the grid---------------------------------
    rndWordList.sort(key=len, reverse=True)  #---sorting the list in descending order of word size
    print(rndWordList)
    for wrds in rndWordList:
        allotWordsToGrid(wrds)

   #----------------checking whether all the words are alloted in the grid or not; if not then allot it----------------   
    for checkWord in rndWordList:
        if checkWord not in wordsAlloted:
            allotWordsToGrid(checkWord)   

   #----------print grid with the all ten words--------------------------
    for r in range(matrixSize):
        for c in range(matrixSize):
            gridLabel=tk.Label(left_frame, text=grid_cells[r][c], padx=6, pady=4, bg='lightblue')
            gridLabel.grid(row=r, column=c)
            gridLabel.bind('<Enter>', highLightText)
            gridLabel.bind('<Leave>', unHighlightText)
            gridLabel.bind('<Button-1>', changeLabelColor)
    print("checking char-----10,10",grid_cells[10][10])




#------ function to allot word-------------------------------
def allotWordsToGrid(wrds):
    leng=len(wrds)

    if leng>=matrixSize-2:         #-------- HANDLE OUT OF RANGE WORDS----------
        print(wrds,leng," is too big for the grid")
        rndWordList.remove(wrds)
        return #exit the function safely
    if leng>matrixSize-6:          #-------- HANDLE ALMOST OUT OF RANGE WORDS----------
        allotLogWordToGrid(wrds,leng)
        return

    randomCoordinate=random.choice(coordinates)
    x,y=map(int, randomCoordinate.split(","))
    if x>matrixSize/2 and y>matrixSize/2:  
        print(x,y,"down right")
        setWordFromDownRight(x,y,wrds,leng)
        return    
    if x>matrixSize/2 and y<matrixSize/2:
        print(x,y,"down left")
        setWordFromDownLeft(x,y,wrds,leng)
        return    
    if x<matrixSize/2 and y<matrixSize/2:  
        print(x,y,"up left")
        setWordFromUpLeft(x,y,wrds,leng)
        return    
    if x<matrixSize/2 and y>matrixSize/2:
        print(x,y,"up right")
        setWordFromUpRight(x,y,wrds,leng)
        return


def allotLogWordToGrid(wrd,leng):     
    randomCoordinate=random.choice(coordiForLongWord)
    print(randomCoordinate)
    x,y=map(int, randomCoordinate.split(","))
    print(x,y,"long word checking--------------leng-",leng)  
    chars=list(wrd)
    for indexForLoop in range(leng):
        tempX=x-indexForLoop
        tempY=y-indexForLoop
        print("---long----",tempX,tempY,chars[indexForLoop])
        cordi=f"{tempX},{tempY}"
        if cordi in usedCoordinates or tempX<0 or tempX>matrixSize-1 or tempY<0 or tempY>matrixSize-1:
            randomCoordinate=random.choice(coordiForLongWord)
            #print(randomCoordinate)
            newX,newY=map(int, randomCoordinate.split(","))
            return allotLogWordToGrid(wrd,leng)
        grid_cells[tempX][tempY]=chars[indexForLoop]
        usedCoordinates.append(cordi)
    print("allotLogWordToGrid done--",wrd)
    wordsAlloted.append(wrd)


def setWordFromDownRight(x,y,wrd,leng):
    chars=list(wrd)
    for indexForLoop in range(leng):
        tempX=x-indexForLoop
        tempY=y-indexForLoop
        print("--------",tempX,tempY,chars[indexForLoop])
        cordi=f"{tempX},{tempY}"
        if cordi in usedCoordinates or tempX<0 or tempX>matrixSize-1 or tempY<0 or tempY>matrixSize-1:
            randomCoordinate=random.choice(coordinates)
            #print(randomCoordinate)
            newX,newY=map(int, randomCoordinate.split(","))
            return setWordFromDownRight(newX,newY,wrd,leng)
        grid_cells[tempX][tempY]=chars[indexForLoop]
        usedCoordinates.append(cordi)
    print("setWordFromDownRight done--",wrd)
    wordsAlloted.append(wrd)


def setWordFromDownLeft(x,y,wrd,leng):
    chars=list(wrd)
    for indexForLoop in range(leng):
        tempX=x-indexForLoop
        tempY=y+indexForLoop
        print("-- * ///----",tempX,tempY,chars[indexForLoop])
        cordi=f"{tempX},{tempY}"
        if cordi in usedCoordinates or tempX<0 or tempX>matrixSize-1 or tempY<0 or tempY>matrixSize-1:
            randomCoordinate=random.choice(coordinates)
            #print(randomCoordinate)
            newX,newY=map(int, randomCoordinate.split(","))
            return setWordFromDownLeft(newX,newY,wrd,leng)
        grid_cells[tempX][tempY]=chars[indexForLoop]
        usedCoordinates.append(cordi)
    print("setWordFromDownLeft done--",wrd)
    wordsAlloted.append(wrd)


def setWordFromUpRight(x,y,wrd,leng):
    chars=list(wrd)
    for indexForLoop in range(leng):
        tempX=x+indexForLoop
        tempY=y-indexForLoop
        print("-----/// * ---",tempX,tempY,chars[indexForLoop])
        cordi=f"{tempX},{tempY}"
        if cordi in usedCoordinates or tempX<0 or tempX>matrixSize-1 or tempY<0 or tempY>matrixSize-1:
            randomCoordinate=random.choice(coordinates)
            #print(randomCoordinate)
            newX,newY=map(int, randomCoordinate.split(","))
            return setWordFromUpRight(newX,newY,wrd,leng)
        grid_cells[tempX][tempY]=chars[indexForLoop]
        usedCoordinates.append(cordi)
    print("setWordFromUpRight done--",wrd)
    wordsAlloted.append(wrd)
           

def setWordFromUpLeft(x,y,wrd,leng):
    chars=list(wrd)
    for indexForLoop in range(leng):
        tempX=x+indexForLoop
        tempY=y+indexForLoop
        print("-++++++++---",tempX,tempY,chars[indexForLoop])
        cordi=f"{tempX},{tempY}"
        if cordi in usedCoordinates or tempX<0 or tempX>matrixSize-1 or tempY<0 or tempY>matrixSize-1:
            randomCoordinate=random.choice(coordinates)
            #print(randomCoordinate)
            newX,newY=map(int, randomCoordinate.split(","))
            return setWordFromUpLeft(newX,newY,wrd,leng)
        grid_cells[tempX][tempY]=chars[indexForLoop]
        usedCoordinates.append(cordi)
    print("setWordFromUpLeft done--",wrd)
    wordsAlloted.append(wrd)
           



#------------------------------------ON LOAD functionality-------------------------------


#----- setting some coordinates for LONG WORDS
for rowCounter in range(matrixSize-3, matrixSize):
    for columnCounter in range(matrixSize-3, matrixSize):
        coord=f"{rowCounter},{columnCounter}"
        coordiForLongWord.append(coord)
print(coordiForLongWord)

getWordsFromFile()

if len(rndWordList)>7 or len(rndWordList)<7:
    getWordsFromFile()


print("checking char-----10,10",grid_cells[10][10])


#----------------------------------------CREATING GUI---------------------------------------------------- 
# creating main tkinter interface and dividing into left and right panel
master = tk.Tk()
master.title("Wordsearch (falling into words)")

left_frame = tk.Frame(master, width=400, height=400, bg='lightblue')
left_frame.grid(row=0, column=0, padx=20, pady=20)
right_frame = tk.Frame(master, width=400, height=400, bg='lightgray')
right_frame.grid(row=0, column=1, padx=20, pady=20)

defaultFont = font.Font(family="Arial", size=12, weight="normal")
boldFont = font.Font(family="Arial", size=13, weight="bold")

# Set default font for Label, Entry and Button widgets
left_frame.option_add("*Label.Font", defaultFont)
right_frame.option_add("*Label.Font", defaultFont)
right_frame.option_add("*Button.Font", defaultFont)
right_frame.option_add("*Entry.Font", defaultFont)
right_frame.option_add("*Listbox.Font", defaultFont)



#--------------------------LEFT PANEL CONTENT STARTS------------------------------------------- 

for rowCounter in range(matrixSize):
    for columnCounter in range(matrixSize):
        tk.Label(left_frame, text=grid_cells[rowCounter][columnCounter], padx=6, pady=4, bg='lightblue').grid(row=rowCounter, column=columnCounter)  
        cordi=f"{rowCounter},{columnCounter}"
        coordinates.append(cordi)
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
buttonQuit=tk.Button(right_frame, text='Quit', command=master.quit)
buttonQuit.grid(row=6, column=1, padx=5, pady=5, sticky='ew')

buttonAddToList=tk.Button(right_frame, text='Add to list', command=addToList)
buttonAddToList.grid(row=5, column=1, padx=5, pady=5, sticky='ew')

timerLabel=tk.Label(right_frame, text='Time : 0 sec')
timerLabel.grid(row=9, column=1, padx=5, pady=5)

tk.Button(right_frame, text='Start', command=startTime).grid(row=10, column=0, padx=5, pady=5, sticky='ew')
tk.Button(right_frame, text='Stop', command=stopTime).grid(row=10, column=1, padx=5, pady=5, sticky='ew')
tk.Button(right_frame, text='Reset', command=resetTime).grid(row=10, column=2, padx=5, pady=5, sticky='ew')

#--------------------------RIGHT PANEL CONTENT ENDS------------------------------------------- 

tk.mainloop()