# app.py
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
from openai import OpenAI
import os
import pandas as pd
import plotly.express as px
from dotenv import load_dotenv, dotenv_values

app = Flask(__name__, template_folder="webPages")

# Load your OpenRouter API key from environment variable
load_dotenv()
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API")

# Initialize the OpenAI client (pointing to OpenRouter)
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=OPENROUTER_API_KEY,
)

# Uploads folder setup
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Read uploaded file content (assuming text-based files)
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        # Compliance check prompt
        prompt = f"""
        Analyze the following cybersecurity policy for non-compliance issues 
        based on ISO 27001 and NIST CSF standards.
        Provide a list of potential risks and mark severity (Low, Medium, High).

        Format:
        Risk: <risk statement>
        Severity: <Low/Medium/High>
        ---

        {content}
        """

        # Call OpenRouter model
        completion = client.chat.completions.create(
            extra_headers={
                "HTTP-Referer": "http://localhost:5000",  # Replace with your site URL
                "X-Title": "Cybersecurity Compliance Checker"
            },
            model="openai/gpt-oss-20b:free",
            messages=[{"role": "user", "content": prompt}]
        )

        result = completion.choices[0].message.content

        # Parse AI output into structured risks
        blocks = result.strip().split('---')
        risks = []
        for block in blocks:
            lines = block.strip().split('\n')
            risk_dict = {}
            for line in lines:
                if line.startswith("Risk:"):
                    risk_dict['risk'] = line.replace("Risk:", "").strip()
                elif line.startswith("Severity:"):
                    risk_dict['severity'] = line.replace("Severity:", "").strip()
            if risk_dict:
                risks.append(risk_dict)

        df = pd.DataFrame(risks)

        # Create severity heatmap
        severity_count = df["severity"].value_counts().reset_index()
        severity_count.columns = ["Severity", "Count"]
        fig = px.density_heatmap(severity_count, x="Severity", y="Count", color_continuous_scale="Reds")
        heatmap_html = fig.to_html(full_html=False)

        return render_template('result.html', risks=risks, heatmap=heatmap_html)

    return "No file uploaded"


if __name__ == "__main__":
    app.run(debug=True)
