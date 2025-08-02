import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Create portfolio table if it doesn't exist
db.execute("""
CREATE TABLE IF NOT EXISTS portfolio (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    symbol TEXT NOT NULL,
    shares INTEGER NOT NULL,
    price REAL NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('buy', 'sell')),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(id)

)
""")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    user_id = session["user_id"]

    # Get user holdings
    rows = db.execute("SELECT symbol, shares FROM portfolio WHERE user_id = ?", user_id)
    holdings = []

    total = 0
    for row in rows:
        quote = lookup(row["symbol"])
        value = row["shares"] * quote["price"]
        total += value
        holdings.append({
            "symbol": row["symbol"],
            "shares": row["shares"],
            "price": usd(quote["price"]),
            "total": usd(value)
        })

    # Get cash
    user = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]
    cash = user["cash"]
    grand_total = total + cash

    return render_template("index.html", holdings=holdings, cash=usd(cash), total=usd(grand_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Validate symbol
        if not symbol:
            return apology("must provide stock symbol", 400)

        # Lookup symbol and check validity
        quote = lookup(symbol.upper())
        if not quote:
            return apology("invalid stock symbol", 400)

        # Validate shares
        if not shares:
            return apology("must provide number of shares", 400)
        try:
            shares = int(shares)
            if shares <= 0:
                return apology("shares must be a positive integer", 400)
        except ValueError:
            return apology("shares must be a valid integer", 400)

        # Calculate total cost
        price_per_share = quote["price"]
        total_cost = price_per_share * shares

        # Check user's cash
        user = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = user[0]["cash"]

        if total_cost > cash:
            return apology("not enough cash", 400)

        # Begin transaction
        try:
            # Deduct cash from user
            db.execute("UPDATE users SET cash = cash - ? WHERE id = ?",
                       total_cost, session["user_id"])

            # Check if user already owns this stock
            existing = db.execute(
                "SELECT * FROM portfolio WHERE user_id = ? AND symbol = ?",
                session["user_id"], quote["symbol"]
            )

            # Update or insert portfolio entry
            if existing:
                db.execute(
                    "UPDATE portfolio SET shares = shares + ? WHERE user_id = ? AND symbol = ?",
                    shares, session["user_id"], quote["symbol"]
                )
            else:
                db.execute(
                    "INSERT INTO portfolio (user_id, symbol, shares) VALUES (?, ?, ?)",
                    session["user_id"], quote["symbol"], shares
                )

            # Record transaction in history
            db.execute(
                "INSERT INTO transactions (user_id, symbol, shares, price, type, timestamp) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
                session["user_id"], quote["symbol"], shares, price_per_share, "buy"
            )

            return redirect("/")

        except Exception as e:
            # If anything goes wrong, display an error message
            return apology(f"Database error: {str(e)}", 500)

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute(
        "SELECT symbol, shares, price, type, timestamp FROM transactions WHERE user_id = ? ORDER BY timestamp DESC",
        session["user_id"]
    )

    for t in transactions:
        t["price"] = usd(t["price"])

    return render_template("history.html", transactions=transactions)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")

        # Validate input
        if not symbol:
            return apology("must provide symbol", 400)

        symbol = symbol.strip().upper()
        quote = lookup(symbol)

        if not quote:
            return apology("invalid symbol", 400)

        return render_template("quote.html", quote=quote)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Debug prints
        print(f"password: '{password}'")
        print(f"confirmation: '{confirmation}'")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 400)

        # Ensure password confirmation was submitted
        elif not confirmation:
            return apology("must confirm password", 400)

        # Ensure password and confirmation match
        elif password != confirmation:
            return apology("password do not match", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure username does not already exist
        if len(rows) != 0:
            return apology("username already exists", 400)

        # Insert new username into database
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)",
                   username, generate_password_hash(password))

        # Query database newly inserted user
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via POST (as by submitting a form via POST)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    user_id = session["user_id"]

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        if not symbol or shares <= 0:
            return apology("must provide valid symbol and shares", 400)

        # Check if user has enough shares
        holding = db.execute("SELECT shares FROM portfolio WHERE user_id = ? AND symbol = ?", user_id, symbol)
        if not holding or holding[0]["shares"] < shares:
            return apology("not enough shares", 400)

        # Lookup current price
        quote = lookup(symbol)
        total_sale = shares * quote["price"]

        # Update portfolio
        if holding[0]["shares"] == shares:
            db.execute("DELETE FROM portfolio WHERE user_id = ? AND symbol = ?", user_id, symbol)
        else:
            db.execute("UPDATE portfolio SET shares = shares - ? WHERE user_id = ? AND symbol = ?", shares, user_id, symbol)

        # Update cash
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", total_sale, user_id)

        # Record transaction
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, type) VALUES (?, ?, ?, ?, ?)",
                   user_id, symbol, -shares, quote["price"], "sell")

        return redirect("/")

    else:
        symbols = db.execute("SELECT symbol FROM portfolio WHERE user_id = ?", user_id)
        return render_template("sell.html", symbols=[row["symbol"] for row in symbols])
