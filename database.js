var sqlite3 = require('sqlite3').verbose()
const getHashedPassword = require("./auth.js").getHashedPassword


const DBSOURCE = "db.sqlite"


const db = new sqlite3.Database(DBSOURCE, (err) => {
    if (err) {
      // Cannot open database
      console.error(err.message)
      throw err
    }else{
        console.log('Connected to the SQLite database.')
        db.run(`CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username text UNIQUE, 
            email text UNIQUE, 
            password text, 
            role boolean, 
            CONSTRAINT email_unique UNIQUE (email)
            CONSTRAINT username_unique UNIQUE (username)
            )`, (err) => {});
        db.run(`CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user integer,
            note text,
            FOREIGN KEY (user)
                REFERENCES users (id)
        )`, (err) => {})
    }
});

module.exports = db