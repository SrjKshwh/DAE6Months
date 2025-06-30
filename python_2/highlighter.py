import tkinter as tk
import tkinter.font as tkFont

root = tk.Tk()
root.title("Mouseover Bold Text")

# Define fonts
normal_font = tkFont.Font(family="Arial", size=12, weight="normal")
bold_font = tkFont.Font(family="Arial", size=12, weight="bold")

# Create labels
label1 = tk.Label(root, text="Hover me!", font=normal_font)
label1.grid(row=0, column=0, padx=10, pady=10)

label2 = tk.Label(root, text="Another label", font=normal_font)
label2.grid(row=0, column=1, padx=10, pady=10)

# Event handlers
def on_enter(event):
    event.widget.config(font=bold_font)

def on_leave(event):
    event.widget.config(font=normal_font)

# Bind events to labels
label1.bind("<Enter>", on_enter)
label1.bind("<Leave>", on_leave)

label2.bind("<Enter>", on_enter)
label2.bind("<Leave>", on_leave)


#--------------------------------------------


def change_color_on_click(event):
  """Changes the background color of the clicked label."""
  event.widget.config(bg="red")  # Change background to red

# Create some labels
label3 = tk.Label(root, text="Click me!", padx=10, pady=10, bg="lightblue")
label3.pack()

label4 = tk.Label(root, text="Click me too!", padx=10, pady=10, bg="lightgreen")
label4.pack()

# Bind the click event to each label
label3.bind("<Button-1>", change_color_on_click)
label4.bind("<Button-1>", change_color_on_click)



#------------------------------------------------------------------------------


def toggle_label_color(event):
  """Toggles the background color of the clicked label."""
  label = event.widget
  original_color = "lightblue"  # Define the original color
  changed_color = "red"  # Define the color to change to

  # Get the current background color of the label
  current_color = label.cget("bg") # Get the current background color of the label

  if current_color == original_color:
    label.config(bg=changed_color)  # Change to the changed color
  else:
    label.config(bg=original_color)  # Change back to the original color



# Create a label with an initial color
label5 = tk.Label(root, text="Click to change color", padx=10, pady=10, bg="lightblue")  # Set initial background color
label5.pack()

# Bind the left mouse button click event to the label
label5.bind("<Button-1>", toggle_label_color) # Bind the left mouse button click event to the label

root.mainloop()
