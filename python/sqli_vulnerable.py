"""
Vulnerable Python code with SQL injection flaws.
For security scanner testing only.
"""
import sqlite3
import mysql.connector


def get_user_by_id_vulnerable(user_id):
    """SQL injection via f-string."""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()


def search_users_vulnerable(name):
    """SQL injection via string concatenation."""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor.execute(query)
    return cursor.fetchall()


def get_products_vulnerable(category):
    """SQL injection via string formatting."""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE category = '%s'" % category)
    return cursor.fetchall()


def find_by_email_vulnerable(email):
    """SQL injection via .format()."""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE email = '{}'".format(email)
    cursor.execute(query)
    return cursor.fetchone()


def mysql_vulnerable(username, password):
    """MySQL SQL injection."""
    conn = mysql.connector.connect(host='localhost', user='root', password='pass')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")
    return cursor.fetchone()


def get_user_safe(user_id):
    """Safe parameterized query."""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
