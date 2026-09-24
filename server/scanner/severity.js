'use strict';

/**
 * severity.js — severity ranking + an overall A–F grade derived from findings.
 */

const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];
const SEVERITY_WEIGHT = { info: 0, low: 4, medium: 12, high: 30, critical: 60 };

// status: pass | warn | fail | info | manual
function gradeFromFindings(findings) {
  let penalty = 0;
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, pass: 0 };
  for (const f of findings) {
    if (f.status === 'pass') {
      counts.pass++;
      continue;
    }
    if (f.status === 'manual' || f.status === 'info') {
      counts.info++;
      continue;
    }
    // fail / warn contribute penalty by severity
    const sev = f.severity || 'low';
    if (counts[sev] != null) counts[sev]++;
    penalty += SEVERITY_WEIGHT[sev] || 0;
  }

  let score = Math.max(0, 100 - penalty);
  let grade;
  if (counts.critical > 0) grade = 'F';
  else if (score >= 90) grade = 'A';
  else if (score >= 80) grade = 'B';
  else if (score >= 65) grade = 'C';
  else if (score >= 50) grade = 'D';
  else grade = 'F';

  return { score, grade, counts };
}

function rank(sev) {
  return SEVERITY_ORDER.indexOf(sev);
}

module.exports = { gradeFromFindings, rank, SEVERITY_ORDER };
