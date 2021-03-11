import os

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Configure CS50 Library to use SQLite database
db = sqlite3.connect("project.db")

# Setting up SQL data stuff
# db = SQL("sqlite:///project.db")
REGISTRANTS = {}

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


# Make sure API key is set
# if not os.environ.get("API_KEY"):
    # raise RuntimeError("API_KEY not set")

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

@app.route("/", methods=["GET", "POST"])
def calculator():
    """Register user"""
    if request.method == "GET":
        plaintext = ""
        return render_template("calculator.html", plaintext=plaintext)
    else:
        if not request.form.get("p"):
            return apology("please enter the p value")
        elif not request.form.get("q"):
            return apology("please enter the q value")
        elif not request.form.get("e"):
            return apology("please enter the e value")
        elif not request.form.get("ciphertext") and not request.form.get("plaintext"):
            return apology("please enter the ciphertext or plaintext")
        else:
            p = int(request.form.get("p"))
            q = int(request.form.get("q"))
            e = int(request.form.get("e"))
            ciphertext = int(request.form.get("ciphertext"))
            n = p*q
            r = (p-1)*(q-1)
            d = pow(modinv(e, (p-1)*(q-1)), 1, ((p-1)*(q-1)))
            plaintext = pow(int(ciphertext), d, n) 
        return render_template("calculator.html", plaintext=plaintext)
       
# @app.route("/")
# def index():
    # """Show dashboard"""
    # # dashboard = db.execute("SELECT * FROM log WHERE volunteer_id=:userid OR beneficiary_id=:userid", userid=session["user_id"])
    # # dashboard = db.execute("select log.*,R.username 'Requester',V.username 'Volunteer' from log left outer join users V on log.volunteer_id =V.id left outer join users R on log.beneficiary_id =R.id WHERE volunteer_id=:userid OR beneficiary_id=:userid", userid=session["user_id"])
    # # for userinfo in dashboard:
        # # task_id = userinfo['task_id']

        # # task = userinfo['task']
        # # volunteer = userinfo['Volunteer']
        # # requester = userinfo['Requester']
        # # # volunteer = db.execute("SELECT username FROM users JOIN log ON users.id=log.volunteer_id WHERE volunteer_id=:userid AND task_id=:taskid", userid=session["user_id"], taskid=task_id)
        # # # if not volunteer:
        # # #     volunteerlol = "Nelfhiabfojsitb "
        # # # else:
        # # #     volunteerlol = volunteer[0]['username']
        # # # print(volunteerlol)
        # # # requester = db.execute("SELECT username FROM users JOIN log ON users.id=log.beneficiary_id WHERE beneficiary_id=:userid AND task_id=:taskid", userid=session["user_id"], taskid=task_id)
        # # month = userinfo['month']
        # # day = userinfo['day']
        # # year = userinfo['year']
    # # comdashboard = db.execute("SELECT * FROM log join users on users.id=log.beneficiary_id")
    # # for cominfo in comdashboard:
        # # task = cominfo['task']
        # # task_id = cominfo['task_id']
        # # username = cominfo['username']
        # # month = cominfo['month']
        # # day = cominfo['day']
        # # year = cominfo['year']
    # return render_template("index.html")


@app.route("/volunteer", methods=["GET", "POST"])
@login_required
def volunteer():
    """Volunteer"""
    if request.method == "GET":
        return render_template("volunteer.html")
    else:
        if not request.form.get("task_id"):
            return apology("please provide the task id")
        elif not db.execute("SELECT task FROM log WHERE task_id=:taskid", taskid=request.form.get("task_id")):
            return apology("please provide a valid task id")
        else:
            db.execute("UPDATE log SET volunteer_id=:userid WHERE task_id=:taskid", userid=session["user_id"], taskid=request.form.get("task_id"))
            #db.execute("INSERT INTO log (id, stock, shares, cost) VALUES (:id, :stock, :shares, :cost)", id=session["user_id"], stock=quote["name"], shares=int(request.form.get("shares")), cost=cost)
            return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/requesthelp", methods=["GET", "POST"])
@login_required
def requesthelp():
    """Request help."""
    if request.method == "GET":
        return render_template("requesthelp.html")
    else:
        if not request.form.get("task"):
            return apology("please provide a task")
        elif not request.form.get("month"):
            return apology("please provide a month")
        elif not request.form.get("day"):
            return apology("please provide a day")
        elif not request.form.get("year"):
            return apology("please provide a year")
        else:
            print(session["user_id"])
            db.execute("INSERT INTO log (beneficiary_id, task, month, day, year) VALUES (:userid, :task, :month, :day, :year)", userid=session["user_id"], task=request.form.get("task"), month=request.form.get("month"), day=request.form.get("day"), year=request.form.get("year"))
            print("execute works")
            return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        if not request.form.get("username"):
            return apology("please choose a username")
        elif not request.form.get("password"):
            return apology("please choose a password")
        elif not request.form.get("confirmation"):
            return apology("please confirm password")
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords did not match - please try again")
        else:
            session["user_id"] = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hashedpwd)", username=request.form.get("username"), hashedpwd=generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8))
        return render_template("login.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)