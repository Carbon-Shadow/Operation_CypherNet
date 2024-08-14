from flask import Flask, render_template, redirect, url_for, flash, jsonify, session
from app.forms import RegistrationForm, LoginForm, ChallengeForm, KillSwitchForm, DatabaseReset
from flask_login import login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, db, login_manager
from app.models import User
from app.timer import Timer, TOTAL_SECONDS

def database_timer():
    challenge_time = session['timer']['current_time']
    minutes, seconds = divmod(challenge_time, 60)
    current_user.time_taken = f"{minutes:02}:{seconds:02}"
    db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and form.username.data == 'admin' and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('admin'))
        elif user and check_password_hash(user.password, form.password.data):
            login_user(user)
            session['start_time'] = datetime.now()
            session['timer'] = Timer(TOTAL_SECONDS).__dict__
            return redirect(url_for('challenge'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    form = DatabaseReset()
    expected_text = "poisectf"

    if form.validate_on_submit():
        user_input = form.text.data.lower()
        if user_input == expected_text:
            User.query.filter(User.username != 'admin').delete()
            db.session.commit()
            flash('Database reset successfully!', 'success')
            return redirect(url_for('leaderboard'))
        else:
            flash('Incorrect! Please try again.', 'danger')

    return render_template('admin.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, password=hashed_password, challenge1_completed=False) #Add new challenges here
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    else:
        for field, errors in form.errors.items():
            for error in errors:
                if 'Passwords must match' in error:
                    flash('Passwords do not match. Please try again.', 'danger')
                if 'That username is taken' in error:
                    flash('That username is taken. Please choose a different one.', 'danger')
    return render_template('register.html', form=form)


@app.route('/leaderboard')
@login_required
def leaderboard():
    users = User.query.order_by(User.time_taken.desc(), User.total_challenges_completed.desc()).filter(User.username != 'admin')# Use order by and count to make the leaderboard (Filter Killswitch order by Time)

    return render_template('leaderboard.html', users=users)


@app.route('/challenge')
@login_required
def challenge():
    return render_template('challenge.html')

@app.route('/times_up')
@login_required
def times_up():
    database_timer()
    return render_template('times_up.html')

#Timer
@app.route("/_timer", methods=["GET", "POST"])
@login_required
def timer():
    if 'timer' not in session:
        session['timer'] = Timer(TOTAL_SECONDS).__dict__
    
    # Retrieve the Timer object from session
    timer = Timer(**session['timer'])
    
    new_time = timer.decrement()
    string_time = timer.format_time()
    session['timer'] = timer.__dict__  # Update the session with the decremented time

    if new_time == 0:
        return jsonify({"result": string_time, "redirect": url_for('times_up')})
    return jsonify({"result": string_time})

@app.route('/challenge_complete')
@login_required
def challenge_complete():
    return render_template('challenge_complete.html')

@app.route('/challenge_list', methods=['GET', 'POST'])
@login_required
def challenge_list():
    form = KillSwitchForm()
    challenge_text = 'C1B3rW4rFaR3'
    
    if form.validate_on_submit():
        user_input = form.text.data
        if user_input == challenge_text:
            current_user.killswitch_activated = True
            database_timer()
            return redirect(url_for('challenge_complete'))
        else:
            flash('Incorrect! Please try again.', 'danger')
    
    return render_template('challenge_list.html', form=form)

### CHALLENGES ###

# Caesar Challenge route
@app.route('/caesar', methods=['GET', 'POST'])
@login_required
def caesar():
    form = ChallengeForm()
    challenge_text = "Odcduv Juxrs"
    expected_text = "lazarus group"

    if form.validate_on_submit():
        user_input = form.text.data.lower()
        if user_input == expected_text:
            current_user.challenge1_completed = True
            current_user.total_challenges_completed += 1
            db.session.commit()
            flash('Congratulations! You have decoded the message correctly. The first letter of the Killswitch code is "C".', 'success')
            return redirect(url_for('challenge_list'))
        else:
            flash('Incorrect! Please try again.', 'danger')

    return render_template('challenges/c1_caesar.html', form=form, challenge_text=challenge_text)

@app.route('/morse', methods=['GET', 'POST'])
@login_required
def morse():
    form = ChallengeForm()
    challenge_text = ".- -. --- -. -.-- -- --- ..- ..."
    expected_text = "anonymous"

    if form.validate_on_submit():
        user_input = form.text.data.lower()
        if user_input == expected_text:
            current_user.challenge2_completed = True
            current_user.total_challenges_completed += 1
            db.session.commit()
            flash('Congratulations! You have decoded the message correctly. The next letter of the Killswitch code is "1".', 'success')
            return redirect(url_for('challenge_list'))
        else:
            flash('Incorrect! Please try again.', 'danger')

    return render_template('challenges/c2_morse.html', form=form, challenge_text=challenge_text)

@app.route('/binary', methods=['GET', 'POST'])
@login_required
def binary():
    form = ChallengeForm()
    challenge_text = "01000001 01010000 01010100 00110001 00110000"
    expected_text = "apt10"

    if form.validate_on_submit():
        user_input = form.text.data.lower()
        if user_input == expected_text:
            current_user.challenge3_completed = True
            current_user.total_challenges_completed += 1
            db.session.commit()
            flash('Congratulations! You have decoded the message correctly. The next letter of the Killswitch code is "B".', 'success')
            return redirect(url_for('challenge_list'))
        else:
            flash('Incorrect! Please try again.', 'danger')

    return render_template('challenges/c3_binary.html', form=form, challenge_text=challenge_text)

@app.route('/atbash', methods=['GET', 'POST'])
@login_required
def atbash():
    form = ChallengeForm()
    challenge_text = "Oraziw Hjfzw"
    expected_text = "lizard squad"

    if form.validate_on_submit():
        user_input = form.text.data.lower()
        if user_input == expected_text:
            current_user.challenge4_completed = True
            current_user.total_challenges_completed += 1
            db.session.commit()
            flash('Congratulations! You have decoded the message correctly. The next letter of the Killswitch code is "3".', 'success')
            return redirect(url_for('challenge_list'))
        else:
            flash('Incorrect! Please try again.', 'danger')

    return render_template('challenges/c4_atbash.html', form=form, challenge_text=challenge_text)

@app.route('/karmasutra', methods=['GET', 'POST'])
@login_required
def karmasutra():
    form = ChallengeForm()
    challenge_text = "AHIGVBAR"
    expected_text = "darkside"

    if form.validate_on_submit():
        user_input = form.text.data.lower()
        if user_input == expected_text:
            current_user.challenge5_completed = True
            current_user.total_challenges_completed += 1
            db.session.commit()
            flash('Congratulations! You have decoded the message correctly. The next letter of the Killswitch code is "r".', 'success')
            return redirect(url_for('challenge_list'))
        else:
            flash('Incorrect! Please try again.', 'danger')

    return render_template('challenges/c5_karmasutra.html', form=form, challenge_text=challenge_text)

@app.route('/rail_fence', methods=['GET', 'POST'])
@login_required
def rail_fence():
    form = ChallengeForm()
    challenge_text = "D.RD AKOELR RVO"
    expected_text = "dark overlord"

    if form.validate_on_submit():
        user_input = form.text.data.lower()
        if user_input == expected_text:
            current_user.challenge6_completed = True
            current_user.total_challenges_completed += 1
            db.session.commit()
            flash('Congratulations! You have decoded the message correctly. The next letter of the Killswitch code is "W".', 'success')
            return redirect(url_for('challenge_list'))
        else:
            flash('Incorrect! Please try again.', 'danger')

    return render_template('challenges/c6_rail_fence.html', form=form, challenge_text=challenge_text)

@app.route('/homophonic', methods=['GET', 'POST'])
@login_required
def homophonic():
    form = ChallengeForm()
    challenge_text = "07 16 39 04 10 22 01"
    expected_text = "lulzsec"

    if form.validate_on_submit():
        user_input = form.text.data.lower()
        if user_input == expected_text:
            current_user.challenge7_completed = True
            current_user.total_challenges_completed += 1
            db.session.commit()
            flash('Congratulations! You have decoded the message correctly. The next letter of the Killswitch code is "4".', 'success')
            return redirect(url_for('challenge_list'))
        else:
            flash('Incorrect! Please try again.', 'danger')

    return render_template('challenges/c7_homophonic.html', form=form, challenge_text=challenge_text)

@app.route('/grandpre', methods=['GET', 'POST'])
@login_required
def grandpre():
    form = ChallengeForm()
    challenge_text = "10 74 27 92 50 47 65 06"
    expected_text = "sandworm"

    if form.validate_on_submit():
        user_input = form.text.data.lower()
        if user_input == expected_text:
            current_user.challenge8_completed = True
            current_user.total_challenges_completed += 1
            db.session.commit()
            flash('Congratulations! You have decoded the message correctly. The next letter of the Killswitch code is "r".', 'success')
            return redirect(url_for('challenge_list'))
        else:
            flash('Incorrect! Please try again.', 'danger')

    return render_template('challenges/c8_grandpre.html', form=form, challenge_text=challenge_text)

@app.route('/null', methods=['GET', 'POST'])
@login_required
def null():
    form = ChallengeForm()
    challenge_text = "Dawn's first light, a subtle mist blankets the land, wrapping it in an enigmatic shroud. A kaleidoscope of colors dances across the horizon, revealing a hidden world of wonder. Radiant beams filter through the canopy, casting intricate patterns on the forest floor. Kinetic energy hums softly, animating the tranquil scene with a gentle rhythm. Moments like these remind us of the universe's boundless beauty. As we journey deeper, the mysteries of existence unfold before our eyes, revealing truths that transcend ordinary understanding. Time seems to stand still, as if acknowledging the profound depth of the cosmos. The grandeur of this cosmic display resonates deeply, awakening a profound sense of connection to the universe. Reflecting on such marvels, we are reminded of our place within the grand tapestry of life."
    expected_text = "darkmatter"

    if form.validate_on_submit():
        user_input = form.text.data.lower()
        if user_input == expected_text:
            current_user.challenge9_completed = True
            current_user.total_challenges_completed += 1
            db.session.commit()
            flash('Congratulations! You have decoded the message correctly. The next letter of the Killswitch code is "F".', 'success')
            return redirect(url_for('challenge_list'))
        else:
            flash('Incorrect! Please try again.', 'danger')

    return render_template('challenges/c9_null.html', form=form, challenge_text=challenge_text)

@app.route('/alphabetical_ranks', methods=['GET', 'POST'])
@login_required
def alphabetical_ranks():
    form = ChallengeForm()
    challenge_text = "Key (5) WJANQ"
    expected_text = "revil"

    if form.validate_on_submit():
        user_input = form.text.data.lower()
        if user_input == expected_text:
            current_user.challenge10_completed = True
            current_user.total_challenges_completed += 1
            db.session.commit()
            flash('Congratulations! You have decoded the message correctly. The next letter of the Killswitch code is "a".', 'success')
            return redirect(url_for('challenge_list'))
        else:
            flash('Incorrect! Please try again.', 'danger')

    return render_template('challenges/c10_alphabetical_ranks.html', form=form, challenge_text=challenge_text)

@app.route('/trithemius', methods=['GET', 'POST'])
@login_required
def trithemius():
    form = ChallengeForm()
    challenge_text = "KQNIVYAIBR"
    expected_text = "jokerstash"

    if form.validate_on_submit():
        user_input = form.text.data.lower()
        if user_input == expected_text:
            current_user.challenge11_completed = True
            current_user.total_challenges_completed += 1
            db.session.commit()
            flash('Congratulations! You have decoded the message correctly. The next letter of the Killswitch code is "R".', 'success')
            return redirect(url_for('challenge_list'))
        else:
            flash('Incorrect! Please try again.', 'danger')

    return render_template('challenges/c11_trithemius.html', form=form, challenge_text=challenge_text)

@app.route('/ubchi', methods=['GET', 'POST'])
@login_required
def ubchi():
    form = ChallengeForm()
    challenge_text = "AAPDNX"
    expected_text = "panda"

    if form.validate_on_submit():
        user_input = form.text.data.lower()
        if user_input == expected_text:
            current_user.challenge12_completed = True
            current_user.total_challenges_completed += 1
            db.session.commit()
            flash('Congratulations! You have decoded the message correctly. The next letter of the Killswitch code is "3".', 'success')
            return redirect(url_for('challenge_list'))
        else:
            flash('Incorrect! Please try again.', 'danger')

    return render_template('challenges/c12_ubchi.html', form=form, challenge_text=challenge_text)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
