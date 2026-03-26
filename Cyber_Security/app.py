from flask import Flask, render_template, request
from analysis import analyze_strength, perform_comparative_hashing
from config import POLICY_CONFIG, HASHING_CONFIG

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    results = None

    if request.method == 'POST':
        password = request.form.get('password', '')

        if password:
            # 1. Run Analysis (Strength and Compromise Check)
            strength_data = analyze_strength(password)

            # 2. Run Comparative Hashing
            hashing_data = perform_comparative_hashing(password)

            # 3. Compile final results for the template
            results = {
                "password_input": password,
                "strength": strength_data,
                "hashing": hashing_data
            }

    # Pass the CONFIGS (Policy and Hash)  to the template for display
    return render_template('index.html', results=results, policy_config=POLICY_CONFIG, hashing_config=HASHING_CONFIG)


if __name__ == '__main__':
    app.run(debug=True)

