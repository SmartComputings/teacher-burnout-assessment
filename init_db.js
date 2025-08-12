const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const db = new sqlite3.Database('./data.db');

db.serialize(() => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS admins (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE,
      password_hash TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS responses (
      id TEXT PRIMARY KEY,
      answers_json TEXT,
      domain_scores_json TEXT,
      overall_score REAL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  const adminId = 'admin-1';
  const email = 'admin@example.com';
  const password = 'Password123!';
  const hash = bcrypt.hashSync(password, 10);

  db.get('SELECT * FROM admins WHERE email = ?', [email], (err, row) => {
    if(!row){
      db.run('INSERT INTO admins(id,email,password_hash) VALUES(?,?,?)', [adminId, email, hash], () => {
        console.log('Created demo admin:', email, password);
        insertDemoResponse();
      });
    } else {
      console.log('Admin already exists');
      insertDemoResponse();
    }
  });

  function insertDemoResponse() {
    const sampleAnswers = {};
    for(let i=1;i<=28;i++) sampleAnswers['q'+i] = Math.floor(Math.random()*5)+1;
    const computeDomainScores = require('./compute_sample_scores');
    const ds = computeDomainScores(sampleAnswers);
    const overall = Object.values(ds).reduce((a,b)=>a+b,0)/Object.keys(ds).length;
    
    db.run('INSERT OR IGNORE INTO responses(id, answers_json, domain_scores_json, overall_score) VALUES(?,?,?,?)', 
      ['demo-1', JSON.stringify(sampleAnswers), JSON.stringify(ds), overall], () => {
        console.log('DB initialized with demo response');
        db.close();
      });
  }
});
