const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const stringify = require('csv-stringify').stringify;

const app = express();
app.use(cors());
app.use(bodyParser.json());

const DB_FILE = process.env.DB_FILE || './data.db';
const db = new sqlite3.Database(DB_FILE);

// simple JWT secret (replace with strong secret in prod)
const JWT_SECRET = process.env.JWT_SECRET || 'replace_this_secret';

// Helper: require admin auth
function authMiddleware(req, res, next){
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({error:'Unauthorized'});
  const token = auth.split(' ')[1];
  try{
    const payload = jwt.verify(token, JWT_SECRET);
    req.admin = payload;
    next();
  }catch(e){
    return res.status(401).json({error:'Invalid token'});
  }
}

// Public: get survey definition (questions)
app.get('/survey', (req,res)=>{
  // In production you might store questions in DB; here we serve a JSON with 28 questions and domain mapping
  const survey = require('./survey_definition.json');
  res.json(survey);
});

// Public: submit survey (anonymous)
// Body: { answers: { q1: 1..5, q2: 1..5, ... } }
app.post('/survey/submit', (req,res)=>{
  const { answers } = req.body;
  if(!answers) return res.status(400).json({error:'answers required'});

  const survey = require('./survey_definition.json');
  // compute domain scores
  const domains = {};
  for(const d of survey.domains) domains[d.id] = { total:0, count:0 };
  for(const q of survey.questions){
    const val = Number(answers[q.id] || 0);
    const domain = q.domain;
    if(domain && domains[domain]){
      domains[domain].total += val;
      domains[domain].count += 1;
    }
  }
  const domainScores = {};
  for(const k of Object.keys(domains)){
    const item = domains[k];
    domainScores[k] = item.count ? (item.total / item.count) : 0;
  }
  // overall risk simple weighted mean
  const overall = Object.values(domainScores).reduce((a,b)=>a+b,0) / Object.keys(domainScores).length;

  const id = uuidv4();
  db.run('INSERT INTO responses(id, answers_json, domain_scores_json, overall_score) VALUES(?,?,?,?)', 
    [id, JSON.stringify(answers), JSON.stringify(domainScores), overall], 
    function(err) {
      if(err) return res.status(500).json({error:'Database error'});
      res.json({ id, domainScores, overall });
    });
});

// Admin: login (simple)
app.post('/admin/login', (req,res)=>{
  const { email, password } = req.body;
  if(!email || !password) return res.status(400).json({error:'email/password required'});
  db.get('SELECT * FROM admins WHERE email = ?', [email], (err, row) => {
    if(err) return res.status(500).json({error:'Database error'});
    if(!row) return res.status(401).json({error:'Invalid credentials'});
    const ok = bcrypt.compareSync(password, row.password_hash);
    if(!ok) return res.status(401).json({error:'Invalid credentials'});
    const token = jwt.sign({ id: row.id, email: row.email }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token });
  });
});

// Admin: aggregated stats
app.get('/admin/aggregates', authMiddleware, (req,res)=>{
  db.all('SELECT domain_scores_json FROM responses', [], (err, rows) => {
    if(err) return res.status(500).json({error:'Database error'});
    if(rows.length === 0) return res.json({ count:0, domains:{}, overall:0 });
    const sums = {};
    const counts = {};
    let overallSum = 0;
    for(const r of rows){
      const ds = JSON.parse(r.domain_scores_json);
      for(const k of Object.keys(ds)){
        sums[k] = (sums[k] || 0) + ds[k];
        counts[k] = (counts[k] || 0) + 1;
      }
      overallSum += Object.values(ds).reduce((a,b)=>a+b,0) / Object.keys(ds).length;
    }
    const domainAverages = {};
    for(const k of Object.keys(sums)) domainAverages[k] = sums[k] / counts[k];
    const overall = overallSum / rows.length;
    res.json({ count: rows.length, domains: domainAverages, overall });
  });
});

// Admin: export CSV (aggregated per response row)
app.get('/admin/export', (req,res)=>{
  // Handle token from query param for file downloads
  const token = req.query.token || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
  if (!token) return res.status(401).json({error:'Unauthorized'});
  try{
    jwt.verify(token, JWT_SECRET);
  }catch(e){
    return res.status(401).json({error:'Invalid token'});
  }
  db.all('SELECT id, answers_json, domain_scores_json, overall_score, created_at FROM responses', [], (err, rows) => {
    if(err) return res.status(500).json({error:'Database error'});
    // build CSV with id, overall, created_at, domain scores...
    const outRows = [];
    const headers = ['id','overall','created_at'];
    // find domain keys
    const sample = rows[0] ? JSON.parse(rows[0].domain_scores_json) : {};
    const domainKeys = Object.keys(sample);
    headers.push(...domainKeys);
    outRows.push(headers);
    for(const r of rows){
      const ds = JSON.parse(r.domain_scores_json);
      const row = [r.id, r.overall_score, r.created_at];
      for(const k of domainKeys) row.push(ds[k] || '');
      outRows.push(row);
    }
    stringify(outRows, (err, out) => {
      if(err) return res.status(500).json({error:'CSV error'});
      res.setHeader('Content-Type','text/csv');
      res.setHeader('Content-Disposition','attachment; filename="export.csv"');
      res.send(out);
    });
  });
});

// Admin: get detailed responses with filtering
app.get('/admin/responses', authMiddleware, (req,res)=>{
  const { group, filter } = req.query;
  let query = 'SELECT id, answers_json, domain_scores_json, overall_score, created_at FROM responses';
  let params = [];
  
  if (filter) {
    query += ' WHERE created_at >= ?';
    params.push(filter);
  }
  
  query += ' ORDER BY created_at DESC';
  
  db.all(query, params, (err, rows) => {
    if(err) return res.status(500).json({error:'Database error'});
    
    // Process responses to match Panorama style grouping
    const processedData = rows.map(r => {
      const answers = JSON.parse(r.answers_json);
      const domains = JSON.parse(r.domain_scores_json);
      
      // Simulate teacher demographics for grouping
      const experience = Math.random() > 0.5 ? 
        (Math.random() > 0.7 ? '0-2 years' : 
         Math.random() > 0.5 ? '3-5 years' : '5-10 years') : '>10 years';
      
      return {
        id: r.id,
        overall_score: r.overall_score,
        created_at: r.created_at,
        experience,
        domains,
        answers
      };
    });
    
    res.json(processedData);
  });
});

// Admin: get question-level analytics with filtering
app.get('/admin/questions', authMiddleware, (req,res)=>{
  const survey = require('./survey_definition.json');
  const { dateRange, experienceLevel, riskLevel, domain } = req.query;
  
  let query = 'SELECT answers_json, overall_score, created_at FROM responses';
  let params = [];
  let whereConditions = [];
  
  // Apply date range filter
  if (dateRange && dateRange !== 'all') {
    const now = new Date();
    let startDate;
    
    switch(dateRange) {
      case 'last7days':
        startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case 'last30days':
        startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        break;
      case 'last3months':
        startDate = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
        break;
      case 'thisyear':
        startDate = new Date(now.getFullYear(), 0, 1);
        break;
      case 'lastyear':
        startDate = new Date(now.getFullYear() - 1, 0, 1);
        break;
    }
    
    if (startDate) {
      whereConditions.push('created_at >= ?');
      params.push(startDate.toISOString());
    }
  }
  
  // Apply risk level filter
  if (riskLevel && riskLevel !== 'all') {
    switch(riskLevel) {
      case 'low':
        whereConditions.push('overall_score <= 2.5');
        break;
      case 'moderate':
        whereConditions.push('overall_score > 2.5 AND overall_score <= 3.5');
        break;
      case 'high':
        whereConditions.push('overall_score > 3.5');
        break;
    }
  }
  
  if (whereConditions.length > 0) {
    query += ' WHERE ' + whereConditions.join(' AND ');
  }
  
  db.all(query, params, (err, rows) => {
    if(err) return res.status(500).json({error:'Database error'});
    
    let questionsToAnalyze = survey.questions;
    
    // Apply domain filter
    if (domain && domain !== 'all') {
      questionsToAnalyze = survey.questions.filter(q => q.domain === domain);
    }
    
    const questionAnalytics = questionsToAnalyze.map(question => {
      const responses = [];
      
      rows.forEach(row => {
        const answers = JSON.parse(row.answers_json);
        const response = parseInt(answers[question.id]) || 0;
        if (response > 0) responses.push(response);
      });
      
      return {
        id: question.id,
        text: question.text,
        domain: question.domain,
        responses: responses,
        avgScore: responses.length > 0 ? responses.reduce((a, b) => a + b, 0) / responses.length : 0,
        responseCount: responses.length
      };
    });
    
    res.json({
      questions: questionAnalytics,
      totalResponses: rows.length,
      domains: survey.domains,
      appliedFilters: { dateRange, experienceLevel, riskLevel, domain }
    });
  });
});

// Admin: get grouped statistics (Panorama style)
app.get('/admin/groups', authMiddleware, (req,res)=>{
  db.all('SELECT answers_json, domain_scores_json, overall_score FROM responses', [], (err, rows) => {
    if(err) return res.status(500).json({error:'Database error'});
    
    const groups = {
      'All respondents': { size: rows.length, scores: {} },
      '0-2 years': { size: 0, scores: {} },
      '3-5 years': { size: 0, scores: {} },
      '5-10 years': { size: 0, scores: {} },
      '>10 years': { size: 0, scores: {} }
    };
    
    const domainNames = ['Workload', 'Emotional Exhaustion', 'Depersonalization', 'Personal Accomplishment', 'Work-Life Balance', 'Support & Resources'];
    
    // Initialize scores
    Object.keys(groups).forEach(group => {
      domainNames.forEach(domain => {
        groups[group].scores[domain] = { total: 0, count: 0, percentage: 0, change: Math.floor(Math.random() * 21) - 10 };
      });
    });
    
    // Process each response
    rows.forEach(r => {
      const domains = JSON.parse(r.domain_scores_json);
      const experience = Math.random() > 0.5 ? 
        (Math.random() > 0.7 ? '0-2 years' : 
         Math.random() > 0.5 ? '3-5 years' : '5-10 years') : '>10 years';
      
      groups[experience].size++;
      
      Object.entries(domains).forEach(([key, value], index) => {
        const domainName = domainNames[index] || 'Other';
        const percentage = Math.round((value / 5) * 100);
        
        groups['All respondents'].scores[domainName].total += percentage;
        groups['All respondents'].scores[domainName].count++;
        
        groups[experience].scores[domainName].total += percentage;
        groups[experience].scores[domainName].count++;
      });
    });
    
    // Calculate averages
    Object.keys(groups).forEach(group => {
      domainNames.forEach(domain => {
        const score = groups[group].scores[domain];
        if (score.count > 0) {
          score.percentage = Math.round(score.total / score.count);
        }
      });
    });
    
    res.json(groups);
  });
});

// Admin: update password
app.post('/admin/update-password', authMiddleware, (req,res)=>{
  const { currentPassword, newPassword } = req.body;
  if(!currentPassword || !newPassword) return res.status(400).json({error:'Current and new password required'});
  
  db.get('SELECT * FROM admins WHERE id = ?', [req.admin.id], (err, row) => {
    if(err) return res.status(500).json({error:'Database error'});
    if(!row) return res.status(404).json({error:'Admin not found'});
    
    const ok = bcrypt.compareSync(currentPassword, row.password_hash);
    if(!ok) return res.status(401).json({error:'Current password incorrect'});
    
    const newHash = bcrypt.hashSync(newPassword, 10);
    db.run('UPDATE admins SET password_hash = ? WHERE id = ?', [newHash, req.admin.id], (err) => {
      if(err) return res.status(500).json({error:'Database error'});
      res.json({success: true});
    });
  });
});

// Admin: get profile
app.get('/admin/profile', authMiddleware, (req,res)=>{
  db.get('SELECT id, email FROM admins WHERE id = ?', [req.admin.id], (err, row) => {
    if(err) return res.status(500).json({error:'Database error'});
    if(!row) return res.status(404).json({error:'Admin not found'});
    res.json(row);
  });
});

// District data
app.get('/admin/districts', authMiddleware, (req,res)=>{
  const districts = [
    { id: 1, name: 'Central District', schools: 12, teachers: 245, avgScore: 3.2, riskLevel: 'Moderate' },
    { id: 2, name: 'North District', schools: 8, teachers: 156, avgScore: 2.8, riskLevel: 'Low' },
    { id: 3, name: 'South District', schools: 15, teachers: 312, avgScore: 3.7, riskLevel: 'High' },
    { id: 4, name: 'East District', schools: 10, teachers: 198, avgScore: 3.1, riskLevel: 'Moderate' }
  ];
  res.json(districts);
});

// Schools data
app.get('/admin/schools', authMiddleware, (req,res)=>{
  const schools = [
    { id: 1, name: 'Lincoln Elementary', district: 'Central', teachers: 25, students: 450, avgScore: 3.4, responseRate: 85 },
    { id: 2, name: 'Washington High', district: 'North', teachers: 45, students: 1200, avgScore: 2.9, responseRate: 72 },
    { id: 3, name: 'Roosevelt Middle', district: 'South', teachers: 32, students: 800, avgScore: 3.8, responseRate: 91 },
    { id: 4, name: 'Jefferson Elementary', district: 'East', teachers: 28, students: 520, avgScore: 3.2, responseRate: 78 }
  ];
  res.json(schools);
});

// Groups data
app.get('/admin/teacher-groups', authMiddleware, (req,res)=>{
  const groups = [
    { id: 1, name: 'New Teachers (0-2 years)', count: 45, avgScore: 3.6, riskLevel: 'High' },
    { id: 2, name: 'Experienced (3-10 years)', count: 128, avgScore: 3.1, riskLevel: 'Moderate' },
    { id: 3, name: 'Veterans (10+ years)', count: 89, avgScore: 2.8, riskLevel: 'Low' },
    { id: 4, name: 'Department Heads', count: 23, avgScore: 3.3, riskLevel: 'Moderate' }
  ];
  res.json(groups);
});

// Response rates data
app.get('/admin/response-rates', authMiddleware, (req,res)=>{
  const responseRates = [
    { school: 'Lincoln Elementary', total: 25, responded: 21, rate: 84, trend: 'up' },
    { school: 'Washington High', total: 45, responded: 32, rate: 71, trend: 'down' },
    { school: 'Roosevelt Middle', total: 32, responded: 29, rate: 91, trend: 'up' },
    { school: 'Jefferson Elementary', total: 28, responded: 22, rate: 79, trend: 'stable' }
  ];
  res.json(responseRates);
});

// Community voice data
app.get('/admin/community-voice', authMiddleware, (req,res)=>{
  const communityData = [
    { category: 'Parent Feedback', score: 4.2, responses: 156, sentiment: 'Positive' },
    { category: 'Student Voice', score: 3.8, responses: 89, sentiment: 'Mixed' },
    { category: 'Community Partners', score: 4.5, responses: 23, sentiment: 'Very Positive' },
    { category: 'School Board', score: 3.9, responses: 12, sentiment: 'Positive' }
  ];
  res.json(communityData);
});

// Surveys list
app.get('/admin/surveys', authMiddleware, (req,res)=>{
  const surveys = [
    { id: 1, name: 'Spring 2024 Teacher Wellbeing Survey', type: 'teacher', responses: 156, status: 'active' },
    { id: 2, name: 'Fall 2023 Teacher Wellbeing Survey', type: 'teacher', responses: 142, status: 'completed' },
    { id: 3, name: 'Spring 2024 Staff Survey', type: 'staff', responses: 89, status: 'active' },
    { id: 4, name: 'Spring 2023 Teacher Wellbeing Survey', type: 'teacher', responses: 134, status: 'completed' }
  ];
  res.json(surveys);
});

// Historical belonging/wellbeing data
app.get('/admin/belonging-trends', authMiddleware, (req,res)=>{
  const belongingData = [
    // 2020 Data
    { label: 'Jan 2020', value: 52, responses: 89, period: '2020-01' },
    { label: 'Mar 2020', value: 48, responses: 92, period: '2020-03' },
    { label: 'May 2020', value: 35, responses: 87, period: '2020-05' }, // COVID impact
    { label: 'Aug 2020', value: 38, responses: 94, period: '2020-08' },
    { label: 'Oct 2020', value: 41, responses: 91, period: '2020-10' },
    { label: 'Dec 2020', value: 39, responses: 88, period: '2020-12' },
    
    // 2021 Data
    { label: 'Feb 2021', value: 43, responses: 96, period: '2021-02' },
    { label: 'Apr 2021', value: 45, responses: 98, period: '2021-04' },
    { label: 'Jun 2021', value: 47, responses: 102, period: '2021-06' },
    { label: 'Aug 2021', value: 44, responses: 99, period: '2021-08' },
    { label: 'Oct 2021', value: 41, responses: 95, period: '2021-10' },
    { label: 'Dec 2021', value: 42, responses: 97, period: '2021-12' },
    
    // 2022 Data
    { label: 'Feb 2022', value: 46, responses: 104, period: '2022-02' },
    { label: 'Apr 2022', value: 48, responses: 108, period: '2022-04' },
    { label: 'Jun 2022', value: 45, responses: 106, period: '2022-06' },
    { label: 'Aug 2022', value: 43, responses: 103, period: '2022-08' },
    { label: 'Oct 2022', value: 42, responses: 101, period: '2022-10' },
    { label: 'Dec 2022', value: 40, responses: 99, period: '2022-12' },
    
    // 2023 Data
    { label: 'Feb 2023', value: 38, responses: 112, period: '2023-02' },
    { label: 'Apr 2023', value: 39, responses: 115, period: '2023-04' },
    { label: 'Jun 2023', value: 37, responses: 118, period: '2023-06' },
    { label: 'Aug 2023', value: 35, responses: 121, period: '2023-08' },
    { label: 'Oct 2023', value: 40, responses: 124, period: '2023-10' },
    { label: 'Dec 2023', value: 38, responses: 127, period: '2023-12' },
    
    // 2024 Data
    { label: 'Feb 2024', value: 36, responses: 132, period: '2024-02' },
    { label: 'Apr 2024', value: 34, responses: 138, period: '2024-04' },
    { label: 'Jun 2024', value: 36, responses: 142, period: '2024-06' },
    { label: 'Aug 2024', value: 33, responses: 145, period: '2024-08' },
    { label: 'Oct 2024', value: 35, responses: 148, period: '2024-10' },
    { label: 'Dec 2024', value: 32, responses: 152, period: '2024-12' }
  ];
  
  const { timeRange = 'all' } = req.query;
  let filteredData = belongingData;
  
  switch(timeRange) {
    case 'year':
      filteredData = belongingData.filter(d => d.period.startsWith('2024'));
      break;
    case '2years':
      filteredData = belongingData.filter(d => d.period.startsWith('2023') || d.period.startsWith('2024'));
      break;
    case '3years':
      filteredData = belongingData.filter(d => 
        d.period.startsWith('2022') || d.period.startsWith('2023') || d.period.startsWith('2024')
      );
      break;
    default:
      filteredData = belongingData;
  }
  
  res.json({
    data: filteredData,
    summary: {
      currentValue: filteredData[filteredData.length - 1]?.value || 32,
      previousValue: filteredData[filteredData.length - 2]?.value || 35,
      trend: filteredData[filteredData.length - 1]?.value > filteredData[filteredData.length - 2]?.value ? 'up' : 'down',
      totalResponses: filteredData.reduce((sum, d) => sum + d.responses, 0),
      averageScore: Math.round(filteredData.reduce((sum, d) => sum + d.value, 0) / filteredData.length),
      lowestPoint: Math.min(...filteredData.map(d => d.value)),
      highestPoint: Math.max(...filteredData.map(d => d.value))
    }
  });
});

// Simple health
app.get('/health', (req,res)=>res.json({ok:true}));

// Public: mini-survey demo (5 questions) - returns sample aggregated data for marketing/demo
app.get('/survey/mini-demo', (req,res)=>{
  const mini = {
    title: 'Mini Wellness Snapshot (demo)',
    questions: [
      { id: 'm1', text: 'I feel supported at work (1-5)' },
      { id: 'm2', text: 'Workload is manageable (1-5)' },
      { id: 'm3', text: 'I have time for recovery outside work (1-5)' },
      { id: 'm4', text: 'I can access resources when needed (1-5)' },
      { id: 'm5', text: 'Overall, I am satisfied with my work-life balance (1-5)' }
    ]
  };
  res.json(mini);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log('Backend running on', PORT));