# app.py
from flask import Flask, render_template, request, jsonify
import os
import openai
import pandas as pd
import plotly.express as px
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configure your OpenAI API key
openai.api_key = os.getenv("OPENAI_API_KEY")

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

        # Read content from the uploaded file
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        # Ask GPT for compliance check (simplified prompt)
        prompt = f"""
        Analyze the following cybersecurity policy for non-compliance issues based on ISO 27001 and NIST CSF standards.
        Provide a list of potential risks and mark severity (Low, Medium, High).

        Format the output like:
        Risk: <risk statement>
        Severity: <Low/Medium/High>
        ---

        {content}
        """

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}]
        )

        result = response['choices'][0]['message']['content']

        # Parse response into risks
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

        # Generate heatmap data
        severity_count = df["severity"].value_counts().reset_index()
        severity_count.columns = ["Severity", "Count"]
        fig = px.density_heatmap(severity_count, x="Severity", y="Count", color_continuous_scale="Reds")
        heatmap_html = fig.to_html(full_html=False)

        return render_template('result.html', risks=risks, heatmap=heatmap_html)
    return "No file uploaded"

if __name__ == '__main__':
    app.run(debug=True)
