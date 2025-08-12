# Import the Flask class from the flask library
from flask import Flask, render_template

# Create an instance of the Flask application
# __name__ is a special variable that gets the name of the current module.
# Flask uses this to know where to look for resources like templates.
app = Flask(__name__)

# Define a route for the root URL ('/') of your website.
# When someone navigates to http://localhost:5000, this function will run.
@app.route('/')
def home():
    """
    This function handles requests to the home page.
    It renders the 'index.html' template.
    """
    # render_template() looks for a file named 'index.html'
    # inside the 'templates' folder.
    return render_template('index.html')

# This is the standard way to run the Flask application.
# It checks if the script is being run directly.
if __name__ == '__main__':
    # The 'debug=True' option enables a development server with automatic reloading.
    # It will automatically restart the server whenever you save changes to your code.
    app.run(debug=True)
