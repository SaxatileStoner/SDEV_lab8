"""Main python file to run flask website
SDEV 300 - Lab 8
@author Christopher Stoner
"""
import hashlib
import csv
import datetime
import pandas as pd
from flask import Flask, render_template, request, flash

app = Flask(__name__)
app.secret_key = 'secret'


def pwrd_acceptable(password: str):
    """
    Checks if the user supplied password contains:
        at LEAST 12 characters long
        1 UPPERCASE character
        1 lowercase character
        1 Number character
        1 Special Character

    # Revision 1: Lab7 -> Lab 8
        Must compare between a list of common passwords to
        determine if the password entered is appropriate

    Args:
        password (String): Password supplied from the user to be checked

    Returns:
        int: returns a integer which is an error code, if <= 0, then the password is acceptable,
        if password < 12 characters, return error code: 1
        if password < 1 UPPERCASE characters, return error code: 2
        if password < 1 lowercase characters, return error code: 3
        if password < 1 Number character, return error code: 4
        if password < 1 Special Character, return error code: 5
        if password is found to be within common_password.txt: 6
    """
    with open('static/common_password.txt', 'r', encoding='UTF8') as file:
        for line in file:
            if line.strip() == password:
                return 6

    count = 0
    for char in password:
        count += 1

    if count < 12:
        return 1

    upper = 0
    lower = 0
    number = 0
    special = 0

    for char in password:
        if char.isupper():
            upper += 1
        if char.islower():
            lower += 1
        if char.isnumeric():
            number += 1
        if not char.isalnum():
            special += 1

    if upper <= 0:
        return 2
    if lower <= 0:
        return 3
    if number <= 0:
        return 4
    if special <= 0:
        return 5

    return 0


def get_data():
    """
    Returns pandas DataFrame object of data.csv
    """
    return pd.read_csv('./data.csv', encoding='UTF8')


def check_data(email: str, password: str):
    """
    Checks if email and password exist in the DataFrame of data.csv
    """
    d_frame = get_data()

    # NOTE, may or maynot need index var
    for i, row in d_frame.iterrows():
        if row['EMAIL'] == email and row['PASSWORD'] == (
                hashlib.sha256(password.encode())).hexdigest():
            return True

    return False


def set_new_pass(email: str, curr_pass: str, new_pass: str):
    """
    Sets new password for a user according to their email, and current password
    swaps the current password for a new password provided

    Args:
        email (str): Email registered with the account
        curr_pass (str): Current password register with the account
        new_pass (str): Password to be changed to

    Returns:
        bool: returns True if the write was successful, otherwise, returns false
    """

    successful_write = False
    if check_data(email, curr_pass):  # Check if the entry looking for exists
        d_frame = get_data()

        for i, row in d_frame.iterrows():
            if row['EMAIL'] == email and row['PASSWORD'] == (
                    hashlib.sha256(curr_pass.encode())).hexdigest():
                d_frame.iloc[i, [-1]] = (
                    hashlib.sha256(new_pass.encode())).hexdigest()
                break

        d_frame.to_csv('data.csv', index=False)

        successful_write = True

    return successful_write


def log_login_fail():
    """
    Logs incorrect login activity and sends data to logger.csv
    logger.csv conatins: index, date, time, IP
    """
    d_frame = pd.read_csv('logger.csv', index_col='index')

    # Grab date, time, and ip address
    access_date = (datetime.date.today()).isoformat()
    access_time = (datetime.datetime.now()).strftime('%H:%M')
    ip_address = request.remote_addr

    # Formatting to make new temp dataframe
    data = {'date': access_date, 'time': access_time, 'IP': ip_address}
    temp_df = pd.DataFrame(data, index=[0])

    # concat a new df to overwrite logger.csv
    new_df = pd.concat([d_frame, temp_df], ignore_index=True)

    # overwrite logger.csv with new information
    new_df.to_csv('logger.csv', index_label='index')


@ app.route('/')
def index():
    """Renders webpage that leads to all other pages/examples
    """
    return render_template('index.html')


@ app.route('/images/')
def images():
    """Renders webpage with at least 4 images
    """
    return render_template('images.html')


@ app.route('/table/')
def table():
    """Renders webpage with table of 4 rows and 3 cols
    """
    return render_template('table.html')


@ app.route('/register-form/', methods=['GET', 'POST'])
def register():
    """
    GET: Renders webpage with register form
    POST: Read user submitted data and append new information to data.csv
    """
    if request.method == 'POST':
        first_name = request.form['first-name']
        last_name = request.form['last-name']
        email = request.form['email']
        password = request.form['password']
        password_conf = request.form['password-conf']

        if not first_name:
            flash('You must enter your first name!')
        elif not last_name:
            flash('You must enter your last name!')
        elif not email:
            flash('You must enter an email address!')
        elif not password:
            flash('You must enter a password!')
        elif not password_conf:
            flash('You must enter your password again in password confirmation!')
        elif password != password_conf:
            flash('password confirmation does not equal inputted password!')
        else:
            # Check if valid password
            exit_code = pwrd_acceptable(password)
            print(exit_code)
            if not exit_code <= 0:
                if exit_code == 1:
                    flash("Password must contain at least 12 characters!")
                if exit_code == 2:
                    flash("Password must contain at least 1 UPPERCASE character!")
                if exit_code == 3:
                    flash("Password must contain at least 1 lowercase character!")
                if exit_code == 4:
                    flash("Password must contain at least 1 digit (0-9) character!")
                if exit_code == 5:
                    flash(
                        "Password must contain at least 1 special (!@#$%^&*) character!")
                if exit_code == 6:
                    flash("Password cannot be within common passwords!")
            else:
                # Password is valid, password is ready to be hashed/encoded,
                # and all data sent to data.csv
                sha256_password = hashlib.sha256(password.encode())
                data = [first_name, last_name, email,
                        sha256_password.hexdigest()]
                with open('./data.csv', 'a', encoding='UTF8', newline='\n') as file:
                    writer = csv.writer(file, delimiter=',')
                    writer.writerow(data)

                flash("User Account Added!")

    return render_template('register-form.html')


@ app.route('/login-form/', methods=['GET', 'POST'])
def login():
    """
    GET: Renders webpage with login form
    POST: Reads user submitted data, checks if data is in the db,
          login successful, otherwise, login fail
    """
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if ALL values have been entered in the form
        if not email:
            flash('You must enter an email address!')
        elif not password:
            flash('You must enter a password!')
        else:
            # Processing and checking db can begin.
            # If success, flash success msg,
            # otherwise, flash failure msg
            sha256_password = hashlib.sha256(
                password.encode())  # encode and hash
            fields = []
            rows = []
            # Read csv file then append to arrays in memory
            with open('./data.csv', 'r', encoding='UTF8', newline='\n') as file:
                reader = csv.reader(file, delimiter=',')
                fields = next(reader)

                for row in reader:
                    rows.append(row)

            for row in rows:
                csv_email = row[fields.index("EMAIL")]
                csv_password = row[fields.index("PASSWORD")]
                # Comparing entered information to every row in email and password columns of csv
                if csv_email == email and csv_password == sha256_password.hexdigest():
                    flash("Login Successful!")
                    break
                # if the row is the last entry without a successful login,
                # then there is no login information
                if row == rows[-1]:
                    flash("Incorrect Login!")
                    log_login_fail()
                    break
    return render_template('login-form.html')


@ app.route('/update-password/', methods=['GET', 'POST'])
def update_pass():
    """Updates a user account's password

    Returns:
        render_template: Renders the template webpage
    """
    if request.method == 'POST':
        email = request.form['email']
        curr_password = request.form['password']
        new_password = request.form['new-password']
        new_password_conf = request.form['new-password-conf']

        if not email:
            flash('You must enter your email address!')
        elif not curr_password:
            flash('You must enter your current password!')
        elif not new_password:
            flash('You must enter your new password!')
        elif not new_password_conf:
            flash('You must confirm your new password!')
        elif new_password != new_password_conf:
            flash('New password is not the same is confirmation password!')
        elif not check_data(email, curr_password):
            flash('User does not exist!')
            log_login_fail()
        else:
            # check password validity
            exit_code = pwrd_acceptable(new_password)
            if not exit_code <= 0:
                if exit_code == 1:
                    flash("New password must contain at least 12 characters!")
                if exit_code == 2:
                    flash("New password must contain at least 1 UPPERCASE character!")
                if exit_code == 3:
                    flash("New password must contain at least 1 lowercase character!")
                if exit_code == 4:
                    flash("New password must contain at least 1 digit (0-9) character!")
                if exit_code == 5:
                    flash(
                        "New password must contain at least 1 special (!@#$%^&*) character!")
                if exit_code == 6:
                    flash("Password cannot be within common passwords!")
            else:
                successful_write = set_new_pass(
                    email, curr_password, new_password)
                if successful_write:
                    flash('Password has been updated!')
                else:
                    flash('Oops! Password was not updated correctly...')

    return render_template('update-password.html')


if __name__ == '__main__':
    app.run(debug=True)
