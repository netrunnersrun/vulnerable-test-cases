/**
 * Vulnerable JavaScript code with SQL injection flaws.
 * For security scanner testing only.
 */

const mysql = require('mysql');
const sqlite3 = require('sqlite3');

function getUserByIdVulnerable(userId) {
    // SQL injection via template literal
    const db = new sqlite3.Database('database.db');
    db.get(`SELECT * FROM users WHERE id = ${userId}`, (err, row) => {
        console.log(row);
    });
}

function searchUsersVulnerable(name) {
    // SQL injection via string concatenation
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'mydb'
    });

    const query = "SELECT * FROM users WHERE name = '" + name + "'";
    connection.query(query, (error, results) => {
        console.log(results);
    });
}

function getProductsVulnerable(category) {
    // SQL injection via template literal
    const connection = mysql.createConnection({});
    connection.query(`SELECT * FROM products WHERE category = '${category}'`, (err, results) => {
        console.log(results);
    });
}

function findByEmailVulnerable(email) {
    // SQL injection via string concatenation
    const db = new sqlite3.Database('database.db');
    const query = "SELECT * FROM users WHERE email = '" + email + "'";
    db.all(query, (err, rows) => {
        console.log(rows);
    });
}

function getUserSafe(userId) {
    // Safe parameterized query
    const connection = mysql.createConnection({});
    connection.query('SELECT * FROM users WHERE id = ?', [userId], (err, results) => {
        console.log(results);
    });
}
