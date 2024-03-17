import os
from flask import Flask, render_template, redirect, url_for, session, flash, request
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

# Load environment variables from .env file
load_dotenv('pass.env')

app = Flask(__name__)

# Secret key should be a random, unique, and secure key
app.secret_key = os.getenv('JWT_SECRET_KEY', 'default_secret_key')
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# OAuth setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get('CLIENT_ID'),
    client_secret=os.environ.get('CLIENT_SECRET'),
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)

# Ensure the upload folder exists
UPLOAD_FOLDER = os.path.join(app.static_folder, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    user_info = session.get('user_info')
    if not user_info:
        return redirect(url_for('show_login'))
    return render_template('index.html', user_info=user_info)

@app.route('/login')
def show_login():
    # Renders the login page with Google Sign-In link
    return render_template('login.html')

@app.route('/google_login')
def google_login():
    # Redirect to Google for authorization
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    # Google redirects back to this route after authorization
    token = google.authorize_access_token()
    resp = google.get('userinfo', token=token)
    user_info = resp.json()
    session['user_info'] = user_info
    # Redirect to the homepage
    return redirect(url_for('index'))

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    # Remove user information from the session
    session.pop('user_info', None)
    # Optional: flash a message to the user
    flash('You have been logged out.')
    # Redirect to the login page
    return redirect(url_for('show_login'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If user does not select file, browser also submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            flash('File successfully uploaded')
            return redirect(url_for('uploaded_files')) 
    # If it's not a POST request or no fi
@app.route('/uploaded_files')
def uploaded_files():
# Assumes your uploaded files are in the 'static/uploads' directory
    image_names = os.listdir(os.path.join(app.static_folder, 'uploads'))
    # Filter out any non-image files if necessary
    image_names = [image for image in image_names if allowed_file(image)]
    return render_template('uploads.html', images=image_names)

@app.route('/delete/<filename>', methods=['POST'])
def delete_image(filename):
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(image_path):
        os.remove(image_path)
        flash(f"{filename} has been deleted.")
    else:
        flash(f"Error: {filename} not found.")
    return redirect(url_for('uploaded_files'))

if __name__ == '__main__':
    app.run(debug=True)
	