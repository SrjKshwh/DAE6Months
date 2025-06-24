import tkinter as tk
import random


i=1
rndWordList=[]
with open("C:/Users/saroj/OneDrive/Desktop/course/python_1/listTextFile.txt", "r") as file:
    allText = file.read()
    words = list(map(str, allText.split()))
    for i in range(7):
        randomWord=random.choice(words)
        if randomWord in rndWordList:
            randomWord=random.choice(words)
        else:
            rndWordList.append(randomWord)
print(rndWordList)


def show_entry_fields():
    print("1--: %s\n2--: %s\n3--: %s" % (e1.get(), e2.get(), e3.get()))
    rndWordList.append(e1.get())
    rndWordList.append(e2.get())
    rndWordList.append(e3.get())
    print(rndWordList)
    

master = tk.Tk()
tk.Label(master, text="1st word").grid(row=1)
tk.Label(master, text="2nd word").grid(row=2)
tk.Label(master, text="3rd word").grid(row=3)

e1 = tk.Entry(master)
e2 = tk.Entry(master)
e3 = tk.Entry(master)

e1.grid(row=1, column=1)
e2.grid(row=2, column=1)
e3.grid(row=3, column=1)

tk.Button(master, text='Quit', command=master.quit).grid(row=4, column=0, sticky=tk.W, pady=4)
tk.Button(master, text='Show', command=show_entry_fields).grid(row=5, column=1, sticky=tk.W, pady=4)

tk.mainloop()
    
