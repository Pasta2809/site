const express = require('express');
const session = require('express-session');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const multer = require('multer');
const fs = require('fs');
const archiver = require('archiver');

const app = express();
const db = new sqlite3.Database('./db.sqlite');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// セッション
app.use(
  session({
    secret: 'change_this_secret',
    resave: false,
    saveUninitialized: false,
  })
);

// DB テーブル作成
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

  db.run(`
    CREATE TABLE IF NOT EXISTS files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      original_name TEXT NOT NULL,
      stored_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      size INTEGER NOT NULL,
      uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME,
      description TEXT,
      folder TEXT,
      category TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS user_files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      file_id INTEGER NOT NULL,
      assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, file_id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS groups (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      note TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS group_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      group_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      UNIQUE(group_id, user_id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      details TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

// アップロード設定
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}
const storage = multer.diskStorage({
  destination(req, file, cb) {
    cb(null, uploadDir);
  },
  filename(req, file, cb) {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique);
  },
});
const upload = multer({ storage });
const uploadCsv = multer({ storage: multer.memoryStorage() });

// ログ記録
function addLog(userId, action, details) {
  db.run(
    'INSERT INTO logs (user_id, action, details) VALUES (?, ?, ?)',
    [userId || null, action, details || null],
    (err) => {
      if (err) console.error('ログ記録エラー:', err);
    }
  );
}

// 認証関連
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

function requireAdmin(req, res, next) {
  const u = req.session.user;
  const adminRoles = ['root', 'manager', 'file-manager'];
  if (!u || !adminRoles.includes(u.role)) {
    return res.status(403).send(`<!DOCTYPE html>
<html lang="ja">
  <head><meta charset="UTF-8"><title>権限エラー</title></head>
  <body>
    <script>
      alert('このページにアクセスする権限がありません（管理者のみ）');
      window.location.href = '/dashboard';
    </script>
  </body>
</html>`);
  }
  next();
}

function requireRole(req, res, roles) {
  const u = req.session.user;
  if (!u || !roles.includes(u.role)) {
    res.status(403).send(`<!DOCTYPE html>
<html lang="ja">
  <head><meta charset="UTF-8"><title>権限エラー</title></head>
  <body>
    <script>
      alert('この操作を行う権限がありません');
      window.location.href = '/dashboard';
    </script>
  </body>
</html>`);
    return false;
  }
  return true;
}

// テンプレート共通
app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  next();
});

// ---- 認証 ----
app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err || !user) {
      return res.render('login', { error: 'ユーザー名またはパスワードが違います' });
    }
    if (user.is_active === 0) {
      return res.render('login', { error: 'このアカウントは現在無効化されています' });
    }
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.render('login', { error: 'ユーザー名またはパスワードが違います' });
    }
    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role,
      full_name: user.full_name,
    };
    addLog(user.id, 'login', 'ログイン');
    res.redirect('/dashboard');
  });
});

app.get('/logout', (req, res) => {
  const user = req.session.user;
  const uid = user ? user.id : null;
  req.session.destroy(() => {
    if (uid) addLog(uid, 'logout', 'ログアウト');
    res.redirect('/login');
  });
});

// ---- ダッシュボード（マイファイル） ----
app.get('/dashboard', requireLogin, (req, res) => {
  const userId = req.session.user.id;
  const filters = {
    q: req.query.q || '',
    folder: req.query.folder || '',
    category: req.query.category || '',
  };

  let sql = `
    SELECT f.*
    FROM files f
    JOIN user_files uf ON uf.file_id = f.id
    WHERE uf.user_id = ?
  `;
  const params = [userId];

  if (filters.q) {
    sql += ' AND (f.original_name LIKE ? OR f.description LIKE ?)';
    params.push('%' + filters.q + '%', '%' + filters.q + '%');
  }
  if (filters.folder) {
    sql += ' AND f.folder = ?';
    params.push(filters.folder);
  }
  if (filters.category) {
    sql += ' AND f.category LIKE ?';
    params.push('%' + filters.category + '%');
  }

  sql += ' ORDER BY f.uploaded_at DESC';

  db.all(sql, params, (err, files) => {
    if (err) {
      console.error(err);
      return res.sendStatus(500);
    }
    db.all(
      'SELECT DISTINCT folder FROM files WHERE folder IS NOT NULL AND folder <> "" ORDER BY folder',
      [],
      (err2, folderRows) => {
        if (err2) return res.sendStatus(500);
        db.all(
          'SELECT DISTINCT category FROM files WHERE category IS NOT NULL AND category <> "" ORDER BY category',
          [],
          (err3, catRows) => {
            if (err3) return res.sendStatus(500);
            const folders = folderRows.map((r) => r.folder);
            const categories = catRows
              .map((r) => r.category)
              .filter(Boolean)
              .flatMap((c) => c.split(','))
              .map((s) => s.trim())
              .filter((v, i, a) => v && a.indexOf(v) === i)
              .sort();
            res.render('dashboard', {
              files,
              filters,
              folders,
              categories,
            });
          }
        );
      }
    );
  });
});

// ZIP一括ダウンロード
app.post('/files/bulk-zip', requireLogin, (req, res) => {
  const userId = req.session.user.id;
  const ids = []
    .concat(req.body.file_ids || [])
    .map((v) => parseInt(v, 10))
    .filter((v) => !Number.isNaN(v));

  if (!ids.length) {
    return res.redirect('/dashboard');
  }

  const placeholders = ids.map(() => '?').join(',');
  const params = [userId, ...ids];

  db.all(
    `
    SELECT f.*
    FROM files f
    JOIN user_files uf ON uf.file_id = f.id
    WHERE uf.user_id = ?
      AND f.id IN (${placeholders})
  `,
    params,
    (err, rows) => {
      if (err) {
        console.error(err);
        return res.sendStatus(500);
      }
      if (!rows.length) {
        return res.redirect('/dashboard');
      }

      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', 'attachment; filename="files.zip"');

      const archive = archiver('zip', { zlib: { level: 9 } });
      archive.on('error', (err2) => {
        console.error(err2);
        res.status(500).end();
      });
      archive.pipe(res);

      rows.forEach((file) => {
        const filePath = path.join(uploadDir, file.stored_name);
        if (fs.existsSync(filePath)) {
          archive.file(filePath, { name: file.original_name });
        }
      });

      archive.finalize();
      addLog(userId, 'file_bulk_zip', `file_ids=${ids.join(',')}`);
    }
  );
});

// ファイルアクセス確認
function ensureUserFileAccess(req, res, next) {
  const userId = req.session.user.id;
  const fileId = parseInt(req.params.id, 10);
  if (!fileId) return res.sendStatus(404);

  db.get(
    `
    SELECT f.*
    FROM files f
    JOIN user_files uf ON uf.file_id = f.id
    WHERE uf.user_id = ? AND f.id = ?
  `,
    [userId, fileId],
    (err, file) => {
      if (err) {
        console.error(err);
        return res.sendStatus(500);
      }
      if (!file) return res.status(403).send('このファイルにアクセスする権限がありません');
      req.fileRecord = file;
      next();
    }
  );
}

// ダウンロード
app.get('/files/:id/download', requireLogin, ensureUserFileAccess, (req, res) => {
  const file = req.fileRecord;
  const filePath = path.join(uploadDir, file.stored_name);
  if (!fs.existsSync(filePath)) return res.sendStatus(404);
  addLog(req.session.user.id, 'file_download', `file_id=${file.id}`);
  res.download(filePath, file.original_name);
});

// プレビュー
app.get('/files/:id/preview', requireLogin, ensureUserFileAccess, (req, res) => {
  const file = req.fileRecord;
  const filePath = path.join(uploadDir, file.stored_name);
  if (!fs.existsSync(filePath)) return res.sendStatus(404);
  addLog(req.session.user.id, 'file_preview', `file_id=${file.id}`);

  res.setHeader('Content-Type', file.mime_type);
  if (file.mime_type === 'application/pdf' || file.mime_type.startsWith('image/')) {
    res.setHeader('Content-Disposition', 'inline');
  } else {
    res.setHeader('Content-Disposition', 'attachment; filename="' + encodeURIComponent(file.original_name) + '"');
  }
  fs.createReadStream(filePath).pipe(res);
});

// ---- アカウント設定 ----
app.get('/account', requireLogin, (req, res) => {
  res.render('account', { message: null, error: null });
});

app.post('/account', requireLogin, (req, res) => {
  const { current_password, new_password, new_password_confirm } = req.body;
  const userId = req.session.user.id;

  if (!new_password || new_password !== new_password_confirm) {
    return res.render('account', { message: null, error: '新しいパスワードが一致しません' });
  }

  db.get('SELECT * FROM users WHERE id = ?', [userId], async (err, user) => {
    if (err || !user) return res.sendStatus(500);
    const ok = await bcrypt.compare(current_password, user.password_hash);
    if (!ok) {
      return res.render('account', { message: null, error: '現在のパスワードが違います' });
    }
    const hash = await bcrypt.hash(new_password, 10);
    db.run('UPDATE users SET password_hash = ? WHERE id = ?', [hash, userId], (err2) => {
      if (err2) return res.sendStatus(500);
      addLog(userId, 'password_change', 'パスワード変更');
      res.render('account', { message: 'パスワードを変更しました', error: null });
    });
  });
});

// ---- 管理：ユーザー ----
app.get('/admin/users', requireAdmin, (req, res) => {
  if (!requireRole(req, res, ['root', 'manager'])) return;

  const q = req.query.q || '';
  const role = req.query.role || '';
  const status = req.query.status || '';

  let sql = 'SELECT * FROM users WHERE 1=1';
  const params = [];

  if (q) {
    sql += ' AND (username LIKE ? OR full_name LIKE ?)';
    params.push('%' + q + '%', '%' + q + '%');
  }
  if (role) {
    sql += ' AND role = ?';
    params.push(role);
  }
  if (status === 'active') {
    sql += ' AND is_active = 1';
  } else if (status === 'inactive') {
    sql += ' AND is_active = 0';
  }
  sql += ' ORDER BY id ASC';

  db.all(sql, params, (err, users) => {
    if (err) {
      console.error(err);
      return res.sendStatus(500);
    }
    res.render('admin_users', {
      users,
      filters: { q, role, status },
    });
  });
});

// ユーザー作成
app.post('/admin/users/create', requireAdmin, (req, res) => {
  if (!requireRole(req, res, ['root', 'manager'])) return;
  const { username, password, role, full_name, note } = req.body;

  const validRoles = ['root', 'manager', 'file-manager', 'user'];
  let safeRole = validRoles.includes(role) ? role : 'user';
  if (safeRole === 'root' && req.session.user.role !== 'root') {
    safeRole = 'manager';
  }

  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return res.sendStatus(500);
    db.run(
      'INSERT INTO users (username, password_hash, role, full_name, note) VALUES (?, ?, ?, ?, ?)',
      [username, hash, safeRole, full_name || null, note || null],
      function (err2) {
        if (err2) {
          console.error(err2);
          return res.sendStatus(500);
        }
        addLog(req.session.user.id, 'user_create', `user_id=${this.lastID}, username=${username}`);
        res.redirect('/admin/users');
      }
    );
  });
});

// ユーザー編集
app.post('/admin/users/:id/edit', requireAdmin, (req, res) => {
  if (!requireRole(req, res, ['root', 'manager'])) return;
  const id = parseInt(req.params.id, 10);
  const { full_name, note, role } = req.body;

  const validRoles = ['root', 'manager', 'file-manager', 'user'];
  let safeRole = validRoles.includes(role) ? role : 'user';
  if (safeRole === 'root' && req.session.user.role !== 'root') {
    safeRole = 'manager';
  }

  db.run(
    'UPDATE users SET full_name = ?, note = ?, role = ? WHERE id = ?',
    [full_name || null, note || null, safeRole, id],
    function (err) {
      if (err) {
        console.error(err);
        return res.sendStatus(500);
      }
      addLog(req.session.user.id, 'user_edit', `user_id=${id}`);
      res.redirect('/admin/users');
    }
  );
});

// 有効化/無効化
app.post('/admin/users/:id/toggle', requireAdmin, (req, res) => {
  if (!requireRole(req, res, ['root', 'manager'])) return;
  const id = parseInt(req.params.id, 10);
  const { active } = req.body;
  const isActive = active === '1' ? 1 : 0;
  db.run(
    'UPDATE users SET is_active = ? WHERE id = ?',
    [isActive, id],
    function (err) {
      if (err) {
        console.error(err);
        return res.sendStatus(500);
      }
      addLog(req.session.user.id, 'user_toggle', `user_id=${id}, active=${isActive}`);
      res.redirect('/admin/users');
    }
  );
});

// ユーザー削除
app.post('/admin/users/:id/delete', requireAdmin, (req, res) => {
  if (!requireRole(req, res, ['root', 'manager'])) return;
  const id = parseInt(req.params.id, 10);
  db.run('DELETE FROM user_files WHERE user_id = ?', [id], (err) => {
    if (err) console.error(err);
    db.run('DELETE FROM group_users WHERE user_id = ?', [id], (err2) => {
      if (err2) console.error(err2);
      db.run('DELETE FROM users WHERE id = ?', [id], (err3) => {
        if (err3) {
          console.error(err3);
          return res.sendStatus(500);
        }
        addLog(req.session.user.id, 'user_delete', `user_id=${id}`);
        res.redirect('/admin/users');
      });
    });
  });
});

// CSV一括登録
app.post('/admin/users/import', requireAdmin, uploadCsv.single('csv'), async (req, res) => {
  if (!requireRole(req, res, ['root', 'manager'])) return;
  if (!req.file) {
    return res.status(400).send('CSVファイルが選択されていません');
  }
  const text = req.file.buffer.toString('utf-8');
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0);
  if (!lines.length) {
    return res.status(400).send('CSVが空です');
  }

  let startIndex = 0;
  if (lines[0].toLowerCase().includes('username')) startIndex = 1;

  const validRoles = ['root', 'manager', 'file-manager', 'user'];

  function normalizeRole(rawRole) {
    let r = (rawRole || '').trim();
    if (!validRoles.includes(r)) r = 'user';
    if (r === 'root' && req.session.user.role !== 'root') r = 'manager';
    return r;
  }

  async function createUser(username, password, role, full_name, note) {
    return new Promise((resolve, reject) => {
      bcrypt.hash(password, 10, (err, hash) => {
        if (err) return reject(err);
        const safeRole = normalizeRole(role);
        db.run(
          'INSERT INTO users (username, password_hash, role, full_name, note) VALUES (?, ?, ?, ?, ?)',
          [username, hash, safeRole, full_name || null, note || null],
          function (err2) {
            if (err2) return reject(err2);
            addLog(req.session.user.id, 'user_create', `user_id=${this.lastID}, username=${username} (csv)`);
            resolve();
          }
        );
      });
    });
  }

  let successCount = 0;
  let skipCount = 0;
  for (let i = startIndex; i < lines.length; i++) {
    const cols = lines[i].split(',');
    if (cols.length < 2) {
      skipCount++;
      continue;
    }
    const username = cols[0].trim();
    const password = cols[1].trim();
    const full_name = (cols[2] || '').trim();
    const note = (cols[3] || '').trim();
    const role = (cols[4] || '').trim();
    if (!username || !password) {
      skipCount++;
      continue;
    }
    try {
      // eslint-disable-next-line no-await-in-loop
      await createUser(username, password, role, full_name, note);
      successCount++;
    } catch (e) {
      console.error('CSV import error at line', i + 1, e);
      skipCount++;
    }
  }

  console.log('CSV import result: success=%d, skipped=%d', successCount, skipCount);
  res.redirect('/admin/users');
});

// ---- グループ管理 ----
app.get('/admin/groups', requireAdmin, (req, res) => {
  if (!requireRole(req, res, ['root', 'manager'])) return;
  db.all('SELECT * FROM groups ORDER BY id ASC', [], (err, groups) => {
    if (err) {
      console.error(err);
      return res.sendStatus(500);
    }
    db.all(
      'SELECT g.id as group_id, g.name as group_name, u.id as user_id, u.username, u.full_name FROM group_users gu JOIN groups g ON gu.group_id = g.id JOIN users u ON gu.user_id = u.id ORDER BY g.id, u.id',
      [],
      (err2, rows) => {
        if (err2) {
          console.error(err2);
          return res.sendStatus(500);
        }
        res.render('admin_groups', { groups, groupUsers: rows });
      }
    );
  });
});

app.post('/admin/groups/create', requireAdmin, (req, res) => {
  if (!requireRole(req, res, ['root', 'manager'])) return;
  const { name, note } = req.body;
  db.run('INSERT INTO groups (name, note) VALUES (?, ?)', [name, note || null], function(err) {
    if (err) {
      console.error(err);
      return res.sendStatus(500);
    }
    addLog(req.session.user.id, 'group_create', `group_id=${this.lastID}`);
    res.redirect('/admin/groups');
  });
});

app.post('/admin/groups/:id/add-user', requireAdmin, (req, res) => {
  if (!requireRole(req, res, ['root', 'manager'])) return;
  const groupId = parseInt(req.params.id, 10);
  const userId = parseInt(req.body.user_id, 10);
  if (!groupId || !userId) return res.redirect('/admin/groups');
  db.run(
    'INSERT OR IGNORE INTO group_users (group_id, user_id) VALUES (?, ?)',
    [groupId, userId],
    (err) => {
      if (err) {
        console.error(err);
      } else {
        addLog(req.session.user.id, 'group_add_user', `group_id=${groupId}, user_id=${userId}`);
      }
      res.redirect('/admin/groups');
    }
  );
});

app.post('/admin/groups/:id/remove-user', requireAdmin, (req, res) => {
  if (!requireRole(req, res, ['root', 'manager'])) return;
  const groupId = parseInt(req.params.id, 10);
  const userId = parseInt(req.body.user_id, 10);
  db.run('DELETE FROM group_users WHERE group_id = ? AND user_id = ?', [groupId, userId], (err) => {
    if (err) console.error(err);
    else addLog(req.session.user.id, 'group_remove_user', `group_id=${groupId}, user_id=${userId}`);
    res.redirect('/admin/groups');
  });
});

// ---- ファイル管理 ----
app.get('/admin/files', requireAdmin, (req, res) => {
  if (!requireRole(req, res, ['root', 'manager', 'file-manager'])) return;

  const q = req.query.q || '';
  const type = req.query.type || '';
  const expired = req.query.expired || '';
  const from = req.query.from || '';
  const to = req.query.to || '';
  const folder = req.query.folder || '';
  const category = req.query.category || '';

  let sql = 'SELECT * FROM files WHERE 1=1';
  const params = [];

  if (q) {
    sql += ' AND (original_name LIKE ? OR description LIKE ?)';
    params.push('%' + q + '%', '%' + q + '%');
  }
  if (type === 'pdf') {
    sql += " AND mime_type = 'application/pdf'";
  } else if (type === 'image') {
    sql += " AND mime_type LIKE 'image/%'";
  }
  if (expired === 'only') {
    sql += " AND expires_at IS NOT NULL AND expires_at <= datetime('now')";
  } else if (expired === 'no') {
    sql += ' AND expires_at IS NULL';
  } else if (expired === 'has') {
    sql += ' AND expires_at IS NOT NULL';
  }
  if (from) {
    sql += ' AND date(uploaded_at) >= date(?)';
    params.push(from);
  }
  if (to) {
    sql += ' AND date(uploaded_at) <= date(?)';
    params.push(to);
  }
  if (folder) {
    sql += ' AND folder = ?';
    params.push(folder);
  }
  if (category) {
    sql += ' AND category LIKE ?';
    params.push('%' + category + '%');
  }

  sql += ' ORDER BY uploaded_at DESC';

  db.all(sql, params, (err, files) => {
    if (err) {
      console.error(err);
      return res.sendStatus(500);
    }

    db.all(
      'SELECT DISTINCT folder FROM files WHERE folder IS NOT NULL AND folder <> "" ORDER BY folder',
      [],
      (err2, folderRows) => {
        if (err2) {
          console.error(err2);
          return res.sendStatus(500);
        }
        db.all(
          'SELECT DISTINCT category FROM files WHERE category IS NOT NULL AND category <> "" ORDER BY category',
          [],
          (err3, catRows) => {
            if (err3) {
              console.error(err3);
              return res.sendStatus(500);
            }
            const folders = folderRows.map((r) => r.folder);
            const categories = catRows
              .map((r) => r.category)
              .filter(Boolean)
              .flatMap((c) => c.split(','))
              .map((s) => s.trim())
              .filter((v, i, a) => v && a.indexOf(v) === i)
              .sort();

            db.all(
              'SELECT id, username, full_name FROM users WHERE is_active = 1 ORDER BY id',
              [],
              (err4, users) => {
                if (err4) {
                  console.error(err4);
                  return res.sendStatus(500);
                }
                db.all(
                  'SELECT id, name FROM groups ORDER BY id',
                  [],
                  (err5, groups) => {
                    if (err5) {
                      console.error(err5);
                      return res.sendStatus(500);
                    }

                    res.render('admin_files', {
                      files,
                      filters: { q, type, expired, from, to, folder, category },
                      folders,
                      categories,
                      users,
                      groups,
                    });
                  }
                );
              }
            );
          }
        );
      }
    );
  });
});

// ファイルアップロード
app.post('/admin/files/upload', requireAdmin, upload.single('file'), (req, res) => {
  if (!requireRole(req, res, ['root', 'manager', 'file-manager'])) return;
  const file = req.file;
  if (!file) {
    return res.status(400).send('ファイルが選択されていません');
  }
  const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');
  const { expires_date, description, folder, category } = req.body;

  let expiresAt = null;
  if (expires_date) {
    expiresAt = expires_date.trim() + ' 23:59:59';
  }
  const desc = description && description.trim().length > 0 ? description.trim() : null;
  const folderVal = folder && folder.trim().length > 0 ? folder.trim() : null;
  const categoryVal = category && category.trim().length > 0 ? category.trim() : null;

  db.run(
    'INSERT INTO files (original_name, stored_name, mime_type, size, expires_at, description, folder, category) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [originalName, file.filename, file.mimetype, file.size, expiresAt, desc, folderVal, categoryVal],
    function (err) {
      if (err) {
        console.error(err);
        return res.sendStatus(500);
      }
      addLog(req.session.user.id, 'file_upload', `file_id=${this.lastID}, name=${originalName}`);
      res.redirect('/admin/files');
    }
  );
});

// ファイルメタ更新
app.post('/admin/files/update-meta', requireAdmin, (req, res) => {
  if (!requireRole(req, res, ['root', 'manager'])) return;
  const { file_id, description, expires_date, folder, category } = req.body;
  const id = parseInt(file_id, 10);
  if (!id) return res.redirect('/admin/files');

  let expiresAt = null;
  if (expires_date && expires_date.trim().length > 0) {
    expiresAt = expires_date.trim() + ' 23:59:59';
  }
  const desc = description && description.trim().length > 0 ? description.trim() : null;
  const folderVal = folder && folder.trim().length > 0 ? folder.trim() : null;
  const categoryVal = category && category.trim().length > 0 ? category.trim() : null;

  db.run(
    'UPDATE files SET description = ?, expires_at = ?, folder = ?, category = ? WHERE id = ?',
    [desc, expiresAt, folderVal, categoryVal, id],
    function (err) {
      if (err) {
        console.error(err);
        return res.sendStatus(500);
      }
      addLog(req.session.user.id, 'file_update_meta', `file_id=${id}`);
      res.redirect('/admin/files');
    }
  );
});

// ファイル削除
app.post('/admin/files/:id/delete', requireAdmin, (req, res) => {
  if (!requireRole(req, res, ['root', 'manager'])) return;
  const id = parseInt(req.params.id, 10);
  db.get('SELECT * FROM files WHERE id = ?', [id], (err, file) => {
    if (err || !file) {
      return res.redirect('/admin/files');
    }
    const filePath = path.join(uploadDir, file.stored_name);
    db.run('DELETE FROM user_files WHERE file_id = ?', [id], (err2) => {
      if (err2) console.error(err2);
      db.run('DELETE FROM files WHERE id = ?', [id], (err3) => {
        if (err3) {
          console.error(err3);
          return res.sendStatus(500);
        }
        if (fs.existsSync(filePath)) {
          fs.unlink(filePath, () => {});
        }
        addLog(req.session.user.id, 'file_delete', `file_id=${id}, name=${file.original_name}`);
        res.redirect('/admin/files');
      });
    });
  });
});

// ファイル割り当て（ユーザー）
app.post('/admin/files/assign', requireAdmin, (req, res) => {
  if (!requireRole(req, res, ['root', 'manager', 'file-manager'])) return;
  const fileId = parseInt(req.body.file_id, 10);
  const userId = parseInt(req.body.user_id, 10);
  if (!fileId || !userId) return res.redirect('/admin/files');
  db.run(
    'INSERT OR IGNORE INTO user_files (user_id, file_id) VALUES (?, ?)',
    [userId, fileId],
    (err) => {
      if (err) console.error(err);
      else addLog(req.session.user.id, 'file_assign', `file_id=${fileId}, user_id=${userId}`);
      res.redirect('/admin/files');
    }
  );
});

// ファイル割り当て（グループ）
app.post('/admin/files/assign-group', requireAdmin, (req, res) => {
  if (!requireRole(req, res, ['root', 'manager', 'file-manager'])) return;
  const fileId = parseInt(req.body.file_id, 10);
  const groupId = parseInt(req.body.group_id, 10);
  if (!fileId || !groupId) return res.redirect('/admin/files');

  db.all('SELECT user_id FROM group_users WHERE group_id = ?', [groupId], (err, rows) => {
    if (err) {
      console.error(err);
      return res.redirect('/admin/files');
    }
    const stmt = db.prepare('INSERT OR IGNORE INTO user_files (user_id, file_id) VALUES (?, ?)');
    rows.forEach((r) => {
      stmt.run([r.user_id, fileId]);
    });
    stmt.finalize((err2) => {
      if (err2) console.error(err2);
      addLog(req.session.user.id, 'file_assign_group', `file_id=${fileId}, group_id=${groupId}`);
      res.redirect('/admin/files');
    });
  });
});

// ファイル別履歴
app.get('/admin/files/:id/history', requireAdmin, (req, res) => {
  if (!requireRole(req, res, ['root', 'manager'])) return;
  const id = parseInt(req.params.id, 10);
  db.get('SELECT * FROM files WHERE id = ?', [id], (err, file) => {
    if (err || !file) {
      return res.redirect('/admin/files');
    }
    db.all(
      `
      SELECT l.*, u.username, u.full_name
      FROM logs l
      LEFT JOIN users u ON l.user_id = u.id
      WHERE l.action IN ('file_download', 'file_preview')
        AND l.details LIKE ?
      ORDER BY l.created_at DESC
      `,
      ['%file_id=' + id + '%'],
      (err2, logs) => {
        if (err2) {
          console.error(err2);
          return res.sendStatus(500);
        }
        res.render('file_history', { file, logs });
      }
    );
  });
});

// ---- 操作ログ ----
app.get('/admin/logs', requireAdmin, (req, res) => {
  if (!requireRole(req, res, ['root', 'manager'])) return;
  db.all(
    `
    SELECT l.*, u.username, u.full_name
    FROM logs l
    LEFT JOIN users u ON l.user_id = u.id
    ORDER BY l.created_at DESC
    LIMIT 200
  `,
    [],
    (err, rows) => {
      if (err) {
        console.error(err);
        return res.sendStatus(500);
      }
      res.render('logs', { logs: rows });
    }
  );
});

// ---- ルート ----
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.redirect('/login');
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log('Server running at http://localhost:' + PORT);
});
