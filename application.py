import os
import datetime
import vonage
import math

from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from flask_mail import Mail, Message
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from random import randrange
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Set up Heroku's PostgreSQL DB
engine = create_engine(os.getenv("DATABASE_URL"))
# Make sure multiple users can make their own db queries
db = scoped_session(sessionmaker(bind=engine))

# Set up IEX API
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

# Set up Vonage API
client = vonage.Client(key=os.getenv("VONAGE_API_KEY"), secret=os.getenv("VONAGE_API_SECRET"))
verify = vonage.Verify(client)

# Set up Gmail service 
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER")
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_PORT"] = 587
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_USE_TLS"] = True
mail = Mail(app)

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


# Homepage
@app.route("/")
@login_required
def index():

    # Get cash
    lines = db.execute("SELECT cash FROM users WHERE id=:user_id",
                       {"user_id": session["user_id"]}).fetchone()
    cash = float(lines["cash"])

    # Get symbol & shares
    rows = db.execute("SELECT symbol, SUM(shares) FROM stocks WHERE user_id=:user_id GROUP BY symbol HAVING SUM(shares) > 0",
                      {"user_id": session["user_id"]}).fetchall()
    if len(rows) == 0:
        return render_template("index.html", cash=usd(cash))

    # Calculate the Portfolio of Stocks
    symbols = []
    names = []
    shares = []
    price = []
    total = []
    profit = float("{:.2f}".format(0))

    for i in range(len(rows)):
        symbols.append(rows[i]["symbol"])
        names.append(lookup(symbols[i])["name"])
        price.append(lookup(symbols[i])["price"])
        shares.append(rows[i]["sum"])
        total.append(price[i] * float(shares[i]))
        profit += total[i]

    for j in range(len(rows)):
        price[j] = usd(price[j])
        total[j] = usd(total[j])

    grand_total = cash + profit

    # Render Homepage
    return render_template("index.html", rows=range(len(rows)), symbols=symbols, shares=shares,
                           names=names, price=price, total=total, cash=usd(cash), grand_total=usd(grand_total))


# Register Page
@app.route("/register", methods=["GET", "POST"])
def register():

    # Clear the previous session
    session.clear()

    if request.method == "POST":
        # Check input
        username = request.form.get("username")
        password = request.form.get("password")
        phone = request.form.get("phone")

        if not username:
            return apology("must provide username", 403)
        elif not password:
            return apology("must provide password", 403)
        elif not phone:
            return apology("must provide phone", 403)

        # Check username
        users = db.execute("SELECT username FROM users WHERE username=:username", {"username": username}).fetchall()
        if len(users) != 0:
            return apology("username is not available", 400)

        # Insert user to DB
        db.execute("INSERT INTO users (username, hash, phone) VALUES (:username, :hash, :phone)", {"username": username, "hash": generate_password_hash(password), "phone": phone})
        db.commit()

        # Remember which user has logged in
        users = db.execute("SELECT id FROM users WHERE username=:username", {"username": username}).fetchall()
        session["user_id"] = users[0]["id"]

        # Back to Homepage
        return redirect("/")
    else:
        return render_template("register.html")


# Login Page
@app.route("/login", methods=["GET", "POST"])
def login():

    # Clear the previous session
    session.clear()

    if request.method == "POST":
        # Check input
        username = request.form.get("username")
        password = request.form.get("password")
        if not username:
            return apology("must provide username", 403)
        elif not password:
            return apology("must provide password", 403)

        # Get user
        users = db.execute("SELECT * FROM users WHERE username = :username", {"username": username}).fetchall()
        if len(users) != 1 or not check_password_hash(users[0]["hash"], password):
            return apology("invalid username and/or password", 403)

        # Send verify code via phone
        phone = users[0]["phone"]
        response = verify.start_verification(number="+1 306 250 2403", brand="Kei Finance", code_length="6")
        response_id = response["request_id"]
        # verify_time = datetime.datetime.now()

        # Go to Verify Page
        return render_template('phoneVerify.html', response_id=response_id, username=username)
    else:
        return render_template("login.html")


# Loggedin Page
@app.route("/loggedin", methods=["POST"])
def loggedin():

    # Check input
    user_code = request.form.get("user_code")
    response_id = request.form.get("response_id")
    username = request.form.get("username")
    
    if not user_code:
        return apology("must provide verify code", 403)

    # Check phone code
    check_response = verify.check(response_id, code=user_code)
    if check_response["status"] == "0":
        # Remember which user has logged in
        users = db.execute("SELECT * FROM users WHERE username = :username", {"username": username}).fetchall()
        session["user_id"] = users[0]["id"]

        # Back to Homepage
        return redirect("/")
    else:
        return apology("invalid verify code", 403)


# Logout Page
@app.route("/logout")
def logout():

    # Clear the previous session 
    session.clear()

    # Back to Homepage
    return redirect("/")


# Reset Page
@app.route("/reset", methods=["GET", "POST"])
def reset():
    if request.method == "POST":
        # Check input
        username = request.form.get("email")
        if not username:
            return apology("must provide email address", 403)

        # Check username
        users = db.execute("SELECT * FROM users WHERE username = :username",
                    {"username": username}).fetchall()
        if len(users) != 1 or username != users[0]["username"]:
            return apology("invalid username", 403)

        # Send verify code via email
        verify_code = randrange(100000, 1000000)
        msg = Message("Finance: Password Reset", recipients=[username])
        msg.html = "<p><b>{}</b></p>".format(verify_code)
        mail.send(msg)

        # Go to Verify Page
        return render_template('mailVerify.html', username=username, verify_code=verify_code)
    else: 
        return render_template("reset.html")


# Reseted Page
@app.route("/reseted", methods=["POST"])
def reseted():
    # Check input
    user_code = int(request.form.get("user_code"))
    new_password = request.form.get("new_password")
    if not user_code:
        return apology("must provide present password", 403)
    elif not new_password:
        return apology("must provide new password", 403)

    # Check mail code
    if user_code != int(request.form.get("verify_code")):
        return apology("invalid code", 403)

    # Check user
    users = db.execute("SELECT * FROM users WHERE username = :username",
                {"username": request.form.get("email")}).fetchall()
    if len(users) != 1 or request.form.get("email") != users[0]["username"]:
        return apology("invalid username", 403)

    # Check new password
    if check_password_hash(users[0]["hash"], new_password):
        return apology("same password", 403)

    # Update user
    db.execute("UPDATE users SET hash=:hash WHERE id=:id",
            {"hash": generate_password_hash(new_password), "id": users[0]["id"]})
    db.commit()

    # Back to Homepage
    return redirect("/")

# Delete Page
@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete(): 
    if request.method == "POST": 
        # Delete user
        db.execute("DELETE FROM users WHERE id=:id", {"id": session["user_id"]})
        db.commit()

        # Back to Homepage
        return render_template("index.html", deleteMessage="Your account is being deleted.")
    else: 
        return render_template('delete.html')


# Quote Page
@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        # Check input
        symbol = request.form.get("symbol").upper()
        if not symbol:
            return apology("missing symbol", 400)
        quote = lookup(symbol)
        if quote == None:
            return apology("invalid symbol", 400)

        # Return value
        name = quote["name"]
        price = quote["price"]
        return render_template("quoted.html", name=name, symbol=symbol, price=price)
    else:
        return render_template("quote.html")


# Buy Page
@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        # Check input
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")
        if not symbol:
            return apology("missing symbol", 400)
        elif not shares:
            return apology("missing shares", 400)
        quote = lookup(symbol)
        if quote == None:
            return apology("invalid symbol", 400)

        # Check cash
        price = quote["price"]
        total = price * float(shares)
        rows = db.execute("SELECT cash FROM users WHERE id=:user_id",
                          {"user_id": session["user_id"]}).fetchone()
        cash = float(rows["cash"])
        if cash < total:
            return apology("can't afford", 400)

        # Update stock
        date = datetime.datetime.strptime(datetime.datetime.today().strftime("%Y-%m-%d %H:%M:%S"), "%Y-%m-%d %H:%M:%S")
        db.execute("INSERT INTO stocks (symbol, shares, price, date, user_id) VALUES (:symbol, :shares, :price, :date, :user_id)",
                   {"symbol": symbol, "shares": int(shares), "price": price, "date": date, "user_id": session["user_id"]})
        db.commit()

        # Update cash
        cash = cash - total
        db.execute("UPDATE users SET cash=:cash WHERE id=:id",
                   {"cash": cash, "id": session["user_id"]})
        db.commit()

        # Back to Homepage
        return redirect("/")
    else:
        symbol = request.args.get("symbol")
        price = float(request.args.get("price"))

        # Get user's max shares
        rows = db.execute("SELECT cash FROM users WHERE id=:user_id", {"user_id": session["user_id"]}).fetchone()
        cash = float(rows["cash"])
        max_shares = math.floor(cash / price)
        return render_template("buy.html", symbol=symbol, max_shares=max_shares)


# Sell Page
@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():

    # Get symbol & shares
    rows = db.execute("SELECT symbol, SUM(shares) FROM stocks WHERE user_id=:user_id GROUP BY symbol HAVING SUM(shares) > 0",
                      {"user_id": session["user_id"]}).fetchall()

    if request.method == "POST":
        # Check input
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not symbol:
            return apology("missing symbol", 400)
        elif not shares:
            return apology("missing shares", 400)

        # Check shares
        for row in rows:
            if symbol == row["symbol"] and int(shares) > row["sum"]:
                return apology("too many shares", 400)

        # Update stock
        quote = lookup(symbol)
        price = quote["price"]
        date = datetime.datetime.strptime(datetime.datetime.today().strftime("%Y-%m-%d %H:%M:%S"), "%Y-%m-%d %H:%M:%S")
        db.execute("INSERT INTO stocks (symbol, shares, price, date, user_id) VALUES (:symbol, :shares, :price, :date, :user_id)",
                   {"symbol": symbol, "shares": -int(shares), "price": price, "date": date, "user_id": session["user_id"]})
        db.commit()

        # Update cash
        rows = db.execute("SELECT cash FROM users WHERE id=:user_id",
                          {"user_id": session["user_id"]}).fetchone()
        cash = float(rows["cash"])
        total = price * float(shares)
        cash = cash + total
        db.execute("UPDATE users SET cash=:cash WHERE id=:id",
                   {"cash": cash, "id": session["user_id"]})
        db.commit()

        # Back to Homepage
        return redirect("/")
    else:
        return render_template("sell.html", rows=rows)


# History Page
@app.route("/history")
@login_required
def history():

    # Get symbol, shares, price, date
    rows = db.execute("SELECT symbol, shares, price, date FROM stocks WHERE user_id=:user_id ORDER BY date DESC",
                      {"user_id": session["user_id"]}).fetchall()
                      
    # Calculate the Portfolio of Stocks
    symbols = []
    shares = []
    price = []
    dates = []

    for i in range(len(rows)):
        symbols.append(rows[i]["symbol"])
        shares.append(rows[i]["shares"])
        price.append(usd(rows[i]["price"]))
        dates.append(rows[i]["date"])

    # Render History
    return render_template("history.html", rows=range(len(rows)), symbols=symbols, shares=shares,
                           price=price, dates=dates)


# Errorhandler 
def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
