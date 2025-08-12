module.exports = function(answers){
  // Load survey definition to get proper domain mapping
  const survey = require('./survey_definition.json');
  const domains = {};
  
  // Initialize domains
  for(const d of survey.domains) {
    domains[d.id] = { total: 0, count: 0 };
  }
  
  // Calculate domain scores based on survey definition
  for(const q of survey.questions) {
    const val = Number(answers[q.id] || 0);
    if(val > 0 && domains[q.domain]) {
      domains[q.domain].total += val;
      domains[q.domain].count += 1;
    }
  }
  
  // Calculate averages
  const out = {};
  for(const k in domains) {
    out[k] = domains[k].count > 0 ? (domains[k].total / domains[k].count) : 0;
  }
  return out;
};
