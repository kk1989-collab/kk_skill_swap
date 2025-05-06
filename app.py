from flask import Flask, render_template
from flask import Flask, render_template, request
from flask import Flask, render_template, request, redirect, url_for
import mysql.connector
from flask_bcrypt import Bcrypt
from numpy.ma.core import append
from flask import Flask, render_template, request, redirect, url_for, session
from flask import flash

#Connect to your MySQL database
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Krishan@123",
    database="kk_project1"  # e.g., 'kk_dev'
)
print(db)

cursor = db.cursor()

app = Flask(__name__)

app.secret_key = 'Krishan12345'  # Use any random secret string


bcrypt = Bcrypt(app)




@app.route('/test-db')
def test_db():
    cursor.execute("SELECT * FROM users")
    result = cursor.fetchall()
    return str(result)

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Query the database to get the user info
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        print(user)

        if user and bcrypt.check_password_hash(user[3], password):  # user[3] is the password column
            # Login successful, redirect to the dashboard
            session['username'] = user[1]  # assuming name is 2nd column
            session['email'] = user[2]     # assuming email is 3rd column
            session['user_id'] = user[0]    #assuming id is first column
            return redirect(url_for('dashboard'))  # user[1] is the name column
        else:
            return "Invalid email or password. Please try again."

    return render_template('login.html')

@app.route ('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get ('name')
        email = request.form.get ('email')
        password = request.form.get ('password')

        # Check if email already exists
        cursor.execute ("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone ()

        if existing_user:
            return "Email already registered! Please login or use a different email."

        # Hash the password
        hashed_password = bcrypt.generate_password_hash (password).decode ('utf-8')

        # Insert data into MySQL database
        cursor.execute ("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
                        (name, email, hashed_password))
        db.commit ()  # Commit changes to the database

        return f"Thanks for registering, {name}!"

    return render_template ('register.html')


@app.route('/dashboard')
def dashboard():
    username = session.get('username', 'Guest')
    return render_template('dashboard.html', username=username)


@app.route('/post-skill', methods=['GET', 'POST'])
def post_skill():
    if 'user_id' not in session:
        return redirect (url_for ('login'))  # Redirect to login if not logged in

    if request.method == 'POST':
        skill_name = request.form.get('skill_name')
        description = request.form.get('description')

        # Get the logged-in user's id from session
        user_id = session.get('user_id')  # Assuming you saved user's id in session after login
        username = session.get ('username', 'Guest')
        email = session.get ('email', 'guest@example.com')
        print(username)
        print(email)
        print(user_id)

        if not user_id:
            return redirect(url_for('login'))  # If no user is logged in, redirect to login

        # Insert posted skill into database with the correct user_id
        cursor.execute("INSERT INTO skill (user_id, skill_name, description) VALUES (%s, %s, %s)",
                       (user_id, skill_name, description))
        db.commit()
        return redirect(url_for('dashboard'))

    return render_template('skill_post.html')

@app.route('/skill-list')
def skill_list():
    username = session['username']
    if 'user_id' not in session:
        return redirect(url_for('login'))
    cursor.execute("SELECT * FROM skill WHERE user_id = %s", (session['user_id'],))
    skills = cursor.fetchall()
    return render_template('skill_list.html', skills=skills,username=username)


@app.route('/skills')
def skills():
    username = session['username']
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cursor.execute("""SELECT skill.id, skill.skill_name, skill.description, users.name 
        FROM skill 
        JOIN users ON skill.user_id = users.id""")
    skills = cursor.fetchall()
    return render_template('skills.html', skills=skills,username=username)

@app.route('/search-skill', methods=['GET', 'POST'])
def search_skill():
    search_term = ""
    user_id = session.get('user_id')

    if request.method == 'POST':
        search_term = request.form.get('search')

    if search_term:
        query = """
            SELECT skill.id, skill.skill_name, skill.description, users.name, users.id
            FROM skill
            JOIN users ON skill.user_id = users.id
            WHERE skill.skill_name LIKE %s AND skill.user_id != %s
        """
        cursor.execute(query, (f"%{search_term}%", user_id))
    else:
        query = """
            SELECT skill.id, skill.skill_name, skill.description, users.name, users.id
            FROM skill
            JOIN users ON skill.user_id = users.id
            WHERE skill.user_id != %s
        """
        cursor.execute(query, (user_id,))

    skills = cursor.fetchall()

    # Get all skill_ids for which user has already sent requests
    cursor.execute("SELECT skill_id FROM skill_requests WHERE sender_id = %s", (user_id,))
    sent_requests = {row[0] for row in cursor.fetchall()}

    return render_template('search_skill.html', skills=skills, sent_requests=sent_requests, logged_in_user_id=user_id)

@app.route('/send-request/<int:skill_id>', methods=['POST'])
def send_request(skill_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    sender_id = session['user_id']

    # Fetch the skill owner's user_id
    cursor.execute("SELECT user_id FROM skill WHERE id = %s", (skill_id,))
    result = cursor.fetchone()

    if result:
        receiver_id = result[0]

        # Insert into a new requests table
        cursor.execute(
            "INSERT INTO skill_requests (sender_id, receiver_id, skill_id) VALUES (%s, %s, %s)",
            (sender_id, receiver_id, skill_id)
        )
        db.commit()

        return redirect(url_for('search_skill'))
    else:
        return "Skill not found.", 404

@app.route('/view-requests', methods=['GET'])
def view_requests():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    receiver_id = session['user_id']

    # Fetch the received requests from the database
    cursor.execute("""
        SELECT r.id, s.skill_name, u.name, r.status
        FROM skill_requests r
        JOIN skill s ON r.skill_id = s.id
        JOIN users u ON r.sender_id = u.id
        WHERE r.receiver_id = %s AND r.sender_id != r.receiver_id
       
        """, (receiver_id,))

    requests = cursor.fetchall()

    return render_template('view_requests.html', requests=requests)


@app.route('/approve-request/<int:request_id>', methods=['GET'])
def approve_request(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Update the request status to 'approved'
    cursor.execute("""
        UPDATE skill_requests
        SET status = 'approved'
        WHERE id = %s AND receiver_id = %s
    """, (request_id, session['user_id']))
    db.commit()

    return redirect(url_for('view_requests'))


@app.route('/reject-request/<int:request_id>', methods=['GET'])
def reject_request(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Update the request status to 'rejected'
    cursor.execute("""
        UPDATE skill_requests
        SET status = 'rejected'
        WHERE id = %s AND receiver_id = %s
    """, (request_id, session['user_id']))
    db.commit()

    return redirect(url_for('view_requests'))


@app.route('/my-requests')
def my_requests():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    sender_id = session['user_id']

    query = """
        SELECT r.id, s.skill_name, u.name, r.status, r.is_completed
        FROM skill_requests r
        JOIN skill s ON r.skill_id = s.id
        JOIN users u ON r.receiver_id = u.id
        WHERE r.sender_id = %s AND r.receiver_id != r.sender_id;
    """

    cursor.execute(query, (sender_id,))
    sent_requests = cursor.fetchall()

    return render_template('my_requests.html', requests=sent_requests)


@app.route('/chat/<int:request_id>', methods=['GET', 'POST'])
def chat(request_id):
    user_id = session.get('user_id')

    # Check if request is approved before allowing chat
    cursor.execute("SELECT status FROM skill_requests WHERE id = %s", (request_id,))
    request_status = cursor.fetchone()

    if not request_status or request_status[0] != 'approved':
        return "Chat is only available for approved requests.", 403

    # Fetch chat messages
    cursor.execute("""
        SELECT chat.id, chat.message, chat.sender_id, chat.timestamp, users.name
        FROM chat
        JOIN users ON chat.sender_id = users.id
        WHERE chat.request_id = %s
        ORDER BY chat.timestamp ASC
    """, (request_id,))
    messages = cursor.fetchall()

    if request.method == 'POST':
        message = request.form.get('message')
        if message:
            cursor.execute("""
                INSERT INTO chat (request_id, sender_id, receiver_id, message)
                VALUES (%s, %s, (SELECT receiver_id FROM skill_requests WHERE id = %s), %s)
            """, (request_id, user_id, request_id, message))
            db.commit()
            return redirect(url_for('chat', request_id=request_id))

    return render_template('chat.html', messages=messages, request_id=request_id)


@app.route('/mark-complete/<int:request_id>', methods=['POST'])
def mark_complete(request_id):
    user_id = session.get('user_id')

    # Check if user is involved in this request
    cursor.execute("SELECT sender_id, receiver_id FROM skill_requests WHERE id = %s", (request_id,))
    result = cursor.fetchone()

    if result and user_id in result:
        cursor.execute("UPDATE skill_requests SET is_completed = TRUE WHERE id = %s", (request_id,))
        db.commit()
        flash("Skill exchange marked as completed.")
        print("hello")
    else:
        flash("Unauthorized action.")
        print("else part")

    return redirect(url_for('my_requests'))

@app.route('/leave-review/<int:request_id>', methods=['GET', 'POST'])
def leave_review(request_id):
    user_id = session.get('user_id')

    # Check if review already exists
    cursor.execute("SELECT rating, comment FROM reviews WHERE request_id = %s AND reviewer_id = %s", (request_id, user_id))
    existing_review = cursor.fetchone()

    if request.method == 'POST' and not existing_review:
        rating = request.form.get('rating')
        comment = request.form.get('comment')

        cursor.execute("select receiver_id from skill_requests where id =%s", (request_id,))
        reviewee_id = cursor.fetchone()

        if reviewee_id:
            reviewee_id = reviewee_id[0]

        cursor.execute("""
            INSERT INTO reviews (request_id, reviewer_id,reviewee_id, rating, comment)
            VALUES (%s, %s, %s,%s, %s)
        """, (request_id, user_id, reviewee_id, rating, comment))
        db.commit()
        return redirect(url_for('my_requests'))

    return render_template('leave_review.html', request_id=request_id, existing_review=existing_review)

@app.route('/my-given-reviews')
def my_given_reviews():
    print("hello")
    user_id = session.get('user_id')
    print(user_id)
    query = """
        SELECT r.id, s.skill_name, u.name, r.rating, r.comment, r.timestamp
        FROM reviews r
        JOIN skill_requests sr ON r.request_id = sr.id
        JOIN skill s ON sr.skill_id = s.id
        JOIN users u ON r.reviewee_id = u.id
        WHERE r.reviewer_id = %s
        ORDER BY r.timestamp DESC
    """
    cursor.execute(query, (user_id,))
    reviews = cursor.fetchall()

    return render_template('my_given_reviews.html',reviews=reviews)


@app.route('/my-received-reviews')
def my_received_reviews():
    print("hello")
    user_id = session.get('user_id')
    print(user_id)

    cursor.execute ("""
            SELECT r.id, s.skill_name, u.name, r.rating, r.comment, r.timestamp
            FROM reviews r
            JOIN skill_requests sr ON r.request_id = sr.id
            JOIN skill s ON sr.skill_id = s.id
            JOIN users u ON r.reviewer_id = u.id
            WHERE r.reviewee_id = %s
            ORDER BY r.timestamp DESC
        """, (user_id,))
    reviews = cursor.fetchall ()

    return render_template('my_received_reviews.html',reviews=reviews)



@app.route('/profile')
def profile():
    username = session.get('username', 'Guest')
    email = session.get('email', 'guest@example.com')
    return render_template('profile.html', username=username, email=email)

@app.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        original_email = session['email']  # get current logged-in email

        if password:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            cursor.execute("UPDATE users SET name = %s, email = %s, password = %s WHERE email = %s",
                           (name, email, hashed_password, original_email))
        else:
            cursor.execute("UPDATE users SET name = %s, email = %s WHERE email = %s",
                           (name, email, original_email))

        db.commit()

        # Update session too after update
        session['username'] = name
        session['email'] = email

        return redirect(url_for('profile'))

    username = session.get('username', 'Guest')
    email = session.get('email', 'guest@example.com')
    return render_template('edit_profile.html', username=username, email=email)


@app.route ('/edit-skill/<int:skill_id>', methods=['GET', 'POST'])
def edit_skill(skill_id):
    if 'user_id' not in session:
        return redirect (url_for ('login'))

    cursor = db.cursor ()
    if request.method == 'POST':
        new_name = request.form.get ('skill_name')
        new_description = request.form.get ('description')
        cursor.execute ("UPDATE skill SET skill_name=%s, description=%s WHERE id=%s AND user_id=%s",
                        (new_name, new_description, skill_id, session['user_id']))
        db.commit ()
        return redirect (url_for ('skill_list'))

    cursor.execute ("SELECT skill_name, description FROM skill WHERE id=%s AND user_id=%s",
                    (skill_id, session['user_id']))
    skill = cursor.fetchone ()
    return render_template ('edit_skill.html', skill=skill, skill_id=skill_id)


@app.route ('/delete-skill/<int:skill_id>')
def delete_skill(skill_id):
    if 'user_id' not in session:
        return redirect (url_for ('login'))

    cursor = db.cursor ()
    cursor.execute ("DELETE FROM skill WHERE id=%s AND user_id=%s", (skill_id, session['user_id']))
    db.commit ()
    return redirect (url_for ('skill_list'))


@app.route('/logout')
def logout():
    session.clear()  # clear all session data
    return redirect(url_for('login'))  # or home page if you want


if __name__ == '__main__':
    app.run(debug=True)
