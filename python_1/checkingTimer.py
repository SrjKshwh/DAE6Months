import tkinter as tk

# Global variables
seconds = 0
timer_running = False

def update_timer():
    global seconds, timer_running
    if timer_running:
        seconds += 1
        timer_label.config(text=f"Time: {seconds} sec")
        root.after(1000, update_timer)  # call again after 1000ms

def start_timer():
    global timer_running
    if not timer_running:
        timer_running = True
        update_timer()

def stop_timer():
    global timer_running
    timer_running = False

def reset_timer():
    global seconds, timer_running
    timer_running = False
    seconds = 0
    timer_label.config(text="Time: 0 sec")

# Set up the window
root = tk.Tk()
root.title("Timer Example")

# Timer display label
timer_label = tk.Label(root, text="Time: 0 sec", font=("Helvetica", 16))
timer_label.pack(pady=10)

# Control buttons
tk.Button(root, text="Start", command=start_timer).pack(side="left", padx=10)
tk.Button(root, text="Stop", command=stop_timer).pack(side="left", padx=10)
tk.Button(root, text="Reset", command=reset_timer).pack(side="left", padx=10)

root.mainloop()
