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
    '''In this function we are checking whether a word is in the tkinter listbox or not; if the word is present
    in list then change the color of the word to the given color in the variable - changedColor'''
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
        index = listbox.get(0, tk.END).index(makeStringFromLetters)         # Search the listbox for the word
        # Configure the item at the found index to have green foreground color
        listbox.itemconfig(index, {'fg': 'lightgreen'})
        makeStringFromLetters=""
        

def undoClicks():
    '''This function clears all the clicked and highlighted letter back to normal; and loads the fresh grid of letters'''
    global makeStringFromLetters
    makeStringFromLetters=""
    for rowCounter in range(matrixSize):
        for columnCounter in range(matrixSize):
            gridLabel=tk.Label(left_frame, text=grid_cells[rowCounter][columnCounter], padx=6, pady=4, bg='lightblue')
            gridLabel.grid(row=rowCounter, column=columnCounter)
            gridLabel.bind('<Enter>', highLightText)
            gridLabel.bind('<Leave>', unHighlightText)
            gridLabel.bind('<Button-1>', changeLabelColor)


#----This is the main function to start the timer----------
def startTime():
    '''When this function is called, it checks if global variable is False, it will make it True and call another function
    to increase the seconds and prints the time'''
    global timerRunning
    if not timerRunning:
        timerRunning=True
        updateTimer()

def updateTimer():
    '''When this function is called it increaments the seconds shown on the tkinter widget by 1 after every 1000miliseconds'''
    global seconds, timerRunning
    if timerRunning:
        seconds +=1
        timerLabel.config(text=f"Time : {seconds} secs")
        right_frame.after(1000, updateTimer)

def stopTime():
    '''When this funtion is called it pauses the timer shown also clears the string containing containing all the clicks'''
    global timerRunning, makeStringFromLetters
    makeStringFromLetters=""
    timerRunning=False

def resetTime():
    '''This function reset the timer and set it to zero'''
    global seconds, timerRunning
    timerRunning=False
    seconds=0
    timerLabel.config(text="Time 0 sec")

# getting random words from text file
def getWordsFromFile():
    '''This function is used to get unique 7 random words from the text file mentioned in the path in the read mode and store those words in a list(rndWordList) '''
    with open("C:/Users/saroj/OneDrive/Desktop/course/FirstSetup/python_1/listTextFile.txt", "r") as file:
        allText = file.read()
        words = list(map(str, allText.split()))
        count=1
        while count < 8:
            randomWord=random.choice(words)
            if randomWord in rndWordList:
                randomWord=random.choice(words)
            else:
                rndWordList.append(randomWord)
            count+=1
    print(rndWordList)



# add user given words to random above list on button click
def addToList():
    '''This function does the following things:
    Step 1 : adds 3 words given by user to the list(rndWordList)
    Step 2 : then it creates a ListBox widget and shows all 10 words in that listbox 
    Step 3 : for each word in list call allotWordsToGrid() function to allot the words on the grid
    Step 4 : checking whether all the words are alloted on the grid or not; if not alloted then callallotWordsToGrid() for that particular word
    Step 5 : finally print all the alloted word on the grid with mouseEnter, mouseLeave, and mouseClick events'''

    global listbox
    print("1--: %s\n2--: %s\n3--: %s" % (inputBox1.get(), inputBox2.get(), inputBox3.get()))
    rndWordList.append(inputBox1.get().upper())
    rndWordList.append(inputBox2.get().upper())
    rndWordList.append(inputBox3.get().upper())
    print(rndWordList)

    listbox=tk.Listbox(right_frame)
    for item in rndWordList:
        listbox.insert(tk.END, item)
    listbox.grid(row=7, column=1, padx=10, pady=10)
    #inputBox1.grid_forget()
    #inputBox2.grid_forget()  
    #inputBox3.grid_forget()
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
    for rowCounter in range(matrixSize):
        for columnCounter in range(matrixSize):
            gridLabel=tk.Label(left_frame, text=grid_cells[rowCounter][columnCounter], padx=6, pady=4, bg='lightblue')
            gridLabel.grid(row=rowCounter, column=columnCounter)
            gridLabel.bind('<Enter>', highLightText)
            gridLabel.bind('<Leave>', unHighlightText)
            gridLabel.bind('<Button-1>', changeLabelColor)
    print("checking char-----10,10",grid_cells[10][10])




#------ function to allot word-------------------------------
def allotWordsToGrid(wrds):
    leng=len(wrds)

    if leng>=matrixSize-2:         #-------- HANDLE OUT OF RANGE WORDS INSIDE TRY, EXCEPT, AND FINALLY BLOCK----------
        try:
            setWordFromDownRight(xCoordi,yCoordi,wrds,leng)
        except Exception as e:
            print(f"Exception is ",{e})
        finally:
            print(wrds,leng," is too big for the grid")
            rndWordList.remove(wrds)
            return #exit the function safely

    if leng>matrixSize-6:          #-------- HANDLE ALMOST OUT OF RANGE WORDS----------
        allotLogWordToGrid(wrds,leng)
        return

    randomCoordinate=random.choice(coordinates)
    xCoordi,yCoordi=map(int, randomCoordinate.split(","))
    if xCoordi>matrixSize/2 and yCoordi>matrixSize/2:  
        print(xCoordi,yCoordi,"down right")
        setWordFromDownRight(xCoordi,yCoordi,wrds,leng)
        return    
    if xCoordi>matrixSize/2 and yCoordi<matrixSize/2:
        print(xCoordi,yCoordi,"down left")
        setWordFromDownLeft(xCoordi,yCoordi,wrds,leng)
        return    
    if xCoordi<matrixSize/2 and yCoordi<matrixSize/2:  
        print(xCoordi,yCoordi,"up left")
        setWordFromUpLeft(xCoordi,yCoordi,wrds,leng)
        return    
    if xCoordi<matrixSize/2 and yCoordi>matrixSize/2:
        print(xCoordi,yCoordi,"up right")
        setWordFromUpRight(xCoordi,yCoordi,wrds,leng)
        return


def allotLogWordToGrid(wrd,leng):     
    randomCoordinate=random.choice(coordiForLongWord)
    print(randomCoordinate)
    xCoordi,yCoordi=map(int, randomCoordinate.split(","))
    print(xCoordi,yCoordi,"long word checking--------------leng-",leng)  
    chars=list(wrd)
    for indexForLoop in range(leng):
        tempX=xCoordi-indexForLoop
        tempY=yCoordi-indexForLoop
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
inputBox1 = tk.Entry(right_frame)
inputBox2 = tk.Entry(right_frame)
inputBox3 = tk.Entry(right_frame)

# adding input boxes to the grid
inputBox1.grid(row=1, column=1)
inputBox2.grid(row=2, column=1)
inputBox3.grid(row=3, column=1)

# creating buttons and adding to the grid
buttonQuit=tk.Button(right_frame, text='Quit', command=master.quit)
buttonQuit.grid(row=6, column=1, padx=5, pady=5, sticky='ew')

buttonAddToList=tk.Button(right_frame, text='Add to list', command=addToList)
buttonAddToList.grid(row=5, column=1, padx=5, pady=5, sticky='ew')

timerLabel=tk.Label(right_frame, text='Time : 0 sec')
timerLabel.grid(row=9, column=0, padx=5, pady=5)

tk.Button(right_frame, text='Start ', command=startTime).grid(row=9, column=1, padx=5, pady=5, sticky='ew')
tk.Button(right_frame, text='Pause', command=stopTime).grid(row=9, column=2, padx=5, pady=5, sticky='ew')
tk.Button(right_frame, text='Reset', command=resetTime).grid(row=9, column=3, padx=5, pady=5, sticky='ew')
tk.Button(right_frame, text='Undo clicks', command=undoClicks).grid(row=10, column=1, padx=5, pady=5, sticky='ew')

#--------------------------RIGHT PANEL CONTENT ENDS------------------------------------------- 

tk.mainloop()