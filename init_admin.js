const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

const db = new sqlite3.Database('./db.sqlite');

const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'abc12345';

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      is_active INTEGER NOT NULL DEFAULT 1,
      full_name TEXT,
      note TEXT
    )
  `);

  db.get('SELECT * FROM users WHERE username = ?', [ADMIN_USERNAME], (err, row) => {
    if (err) {
      console.error(err);
      process.exit(1);
    }
    if (row) {
      console.log('Admin user already exists.');
      return process.exit(0);
    }

    bcrypt.hash(ADMIN_PASSWORD, 10, (err2, hash) => {
      if (err2) {
        console.error(err2);
        process.exit(1);
      }
      db.run(
        'INSERT INTO users (username, password_hash, role, is_active, full_name, note) VALUES (?, ?, ?, 1, ?, ?)',
        [ADMIN_USERNAME, hash, 'root', 'root', '初期rootユーザー'],
        function (err3) {
          if (err3) {
            console.error(err3);
            process.exit(1);
          }
          console.log('Admin user created.');
          process.exit(0);
        }
      );
    });
  });
});
