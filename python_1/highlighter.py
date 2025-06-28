import tkinter as tk
import random

class DrawingApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.canvas = tk.Canvas(self, width=600, height=400, bg="white")
        self.canvas.pack()

        self.draw_button = tk.Button(self, text="Enable Drawing", command=self.enable_drawing)
        self.draw_button.pack()

        self.start_x = None
        self.start_y = None
        self.current_line = None  # To store the ID of the line being drawn

    def enable_drawing(self):
        # Bind mouse events to the canvas when the button is clicked
        self.canvas.bind("<ButtonPress-1>", self.start_line)
        self.canvas.bind("<B1-Motion>", self.draw_line)
        self.canvas.bind("<ButtonRelease-1>", self.end_line)  # Optional: Bind release if needed

    def start_line(self, event):
        # Store the starting coordinates of the mouse click
        self.start_x = event.x
        self.start_y = event.y

    def draw_line(self, event):
        # Draw random lines as the mouse is dragged
        if self.current_line:
            self.canvas.delete(self.current_line)  # Delete the previous line

        # Generate random color and width
        color = "#%06x" % random.randint(0, 0xFFFFFF)  # Random hex color
        #width = random.randint(1, 5)

        # Create a new line based on the start point and current mouse position
        self.current_line = self.canvas.create_line(
            self.start_x, self.start_y, event.x, event.y, fill='yellow', width=10, stipple='gray50'
        )

    def end_line(self, event):
        # Optional: You can add logic here if you want to do something when the mouse button is released.
        # For this example, we'll just reset the start coordinates and line ID.
        self.start_x = None
        self.start_y = None
        self.current_line = None


if __name__ == "__main__":
    app = DrawingApp()
    app.mainloop()
