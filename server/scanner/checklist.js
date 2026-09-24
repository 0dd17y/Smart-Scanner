'use strict';

/**
 * checklist.js — the full OWASP-based Bug Bounty checklist (from Checklist.pdf),
 * used to render the interactive Manual Checklist pane. Items flagged auto:true
 * are also covered by the automated scanner; the rest need human testing.
 */

const OWASP = 'https://owasp.org/www-project-web-security-testing-guide/';

const CHECKLIST = [
  {
    category: 'Recon on wildcard domain',
    items: [
      'Run amass', 'Run subfinder', 'Run assetfinder', 'Run dnsgen',
      'Run massdns', 'Use httprobe', 'Run aquatone (screenshot for alive host)',
    ],
  },
  {
    category: 'Single Domain',
    items: [
      'Nmap scan', 'Burp crawler', 'ffuf (directory and file fuzzing)',
      'hakrawler/gau/paramspider', 'Linkfinder', 'Url with Android application',
      'Shodan', 'Censys', 'Google dorks', 'Pastebin', 'Github', 'OSINT',
    ],
  },
  {
    category: 'Information Gathering',
    items: [
      { t: 'Manually explore the site' },
      { t: 'Spider/crawl for missed or hidden content', auto: true },
      { t: 'Check for files that expose content (robots.txt, sitemap.xml, .DS_Store)', auto: true },
      'Check the caches of major search engines for publicly accessible sites',
      'Check for differences in content based on User Agent',
      { t: 'Perform Web Application Fingerprinting', auto: true },
      { t: 'Identify technologies used', auto: true },
      'Identify user roles', 'Identify application entry points',
      'Identify client-side code',
      'Identify multiple versions/channels (web, mobile web, mobile app, web services)',
      'Identify co-hosted and related applications',
      { t: 'Identify all hostnames and ports', auto: true },
      'Identify third-party hosted content', 'Identify Debug parameters',
    ],
  },
  {
    category: 'Configuration Management',
    items: [
      { t: 'Check for commonly used application and administrative URLs', auto: true },
      { t: 'Check for old, backup and unreferenced files', auto: true },
      { t: 'Check HTTP methods supported and Cross Site Tracing (XST)', auto: true },
      'Test file extensions handling',
      { t: 'Test for security HTTP headers (CSP, X-Frame-Options, HSTS)', auto: true },
      'Test for policies (Flash, Silverlight, robots)',
      'Test for non-production data in live environment, and vice-versa',
      { t: 'Check for sensitive data in client-side code (API keys, credentials)', auto: true },
    ],
  },
  {
    category: 'Secure Transmission',
    items: [
      { t: 'Check SSL Version, Algorithms, Key length', auto: true },
      { t: 'Check for Digital Certificate Validity (Duration, Signature and CN)', auto: true },
      { t: 'Check credentials only delivered over HTTPS', auto: true },
      { t: 'Check that the login form is delivered over HTTPS', auto: true },
      { t: 'Check session tokens only delivered over HTTPS', auto: true },
      { t: 'Check if HTTP Strict Transport Security (HSTS) in use', auto: true },
    ],
  },
  {
    category: 'Authentication',
    items: [
      { t: 'Test for user enumeration', auto: true },
      'Test for authentication bypass',
      { t: 'Test for bruteforce protection', auto: true },
      'Test password quality rules', 'Test remember me functionality',
      { t: 'Test for autocomplete on password forms/input', auto: true },
      'Test password reset and/or recovery', 'Test password change process',
      'Test CAPTCHA', 'Test multi factor authentication',
      'Test for logout functionality presence',
      { t: 'Test for cache management on HTTP (Pragma, Expires, Max-age)', auto: true },
      { t: 'Test for default logins', auto: true },
      'Test for user-accessible authentication history',
      'Test for out-of-channel notification of account lockouts and password changes',
      'Test for consistent authentication across applications with shared schema / SSO',
    ],
  },
  {
    category: 'Session Management',
    items: [
      { t: 'Establish how session management is handled', auto: true },
      { t: 'Check session tokens for cookie flags (httpOnly and secure)', auto: true },
      { t: 'Check session cookie scope (path and domain)', auto: true },
      { t: 'Check session cookie duration (expires and max-age)', auto: true },
      'Check session termination after a maximum lifetime',
      'Check session termination after relative timeout',
      'Check session termination after logout',
      'Test to see if users can have multiple simultaneous sessions',
      { t: 'Test session cookies for randomness', auto: true },
      'Confirm new session tokens are issued on login, role change and logout',
      'Test for consistent session management across applications',
      'Test for session puzzling',
      { t: 'Test for CSRF and clickjacking', auto: true },
    ],
  },
  {
    category: 'Authorization',
    items: [
      { t: 'Test for path traversal', auto: true },
      'Test for bypassing authorization schema',
      'Test for vertical Access control problems (Privilege Escalation)',
      'Test for horizontal Access control problems',
      'Test for missing authorization',
    ],
  },
  {
    category: 'Data Validation',
    items: [
      { t: 'Test for Reflected Cross Site Scripting', auto: true },
      { t: 'Test for Stored Cross Site Scripting', auto: true },
      'Test for DOM based Cross Site Scripting', 'Test for Cross Site Flashing',
      { t: 'Test for HTML Injection', auto: true },
      { t: 'Test for SQL Injection', auto: true },
      'Test for LDAP Injection', 'Test for ORM Injection',
      { t: 'Test for XML Injection', auto: true },
      { t: 'Test for XXE Injection', auto: true },
      { t: 'Test for SSI Injection', auto: true },
      'Test for XPath Injection', 'Test for XQuery Injection',
      'Test for IMAP/SMTP Injection',
      { t: 'Test for Code Injection', auto: true },
      { t: 'Test for Expression Language Injection (SSTI)', auto: true },
      { t: 'Test for Command Injection', auto: true },
      'Test for Overflow (Stack, Heap and Integer)', 'Test for Format String',
      'Test for incubated vulnerabilities',
      { t: 'Test for HTTP Splitting/Smuggling (CRLF)', auto: true },
      { t: 'Test for HTTP Verb Tampering', auto: true },
      { t: 'Test for Open Redirection', auto: true },
      { t: 'Test for Local File Inclusion', auto: true },
      { t: 'Test for Remote File Inclusion', auto: true },
      'Compare client-side and server-side validation rules',
      { t: 'Test for NoSQL injection', auto: true },
      { t: 'Test for HTTP parameter pollution', auto: true },
      'Test for auto-binding', 'Test for Mass Assignment',
      'Test for NULL/Invalid Session Cookie',
    ],
  },
  {
    category: 'Denial of Service',
    items: [
      { t: 'Test for anti-automation', auto: true },
      { t: 'Test for account lockout', auto: true },
      'Test for HTTP protocol DoS', 'Test for SQL wildcard DoS',
    ],
  },
  {
    category: 'Business Logic',
    items: [
      'Test for feature misuse', 'Test for lack of non-repudiation',
      'Test for trust relationships', 'Test for integrity of data',
      'Test segregation of duties',
    ],
  },
  {
    category: 'Cryptography',
    items: [
      { t: 'Check if data which should be encrypted is not', auto: true },
      'Check for wrong algorithms usage depending on context',
      { t: 'Check for weak algorithms usage', auto: true },
      'Check for proper use of salting', 'Check for randomness functions',
    ],
  },
  {
    category: 'Risky Functionality - File Uploads',
    items: [
      'Test that acceptable file types are whitelisted',
      'Test that file size limits, upload frequency and total file counts are enforced',
      'Test that file contents match the defined file type',
      'Test that all file uploads have Anti-Virus scanning in-place',
      'Test that unsafe filenames are sanitised',
      'Test that uploaded files are not directly accessible within the web root',
      'Test that uploaded files are not served on the same hostname/port',
      'Test that files and media are integrated with the auth schemas',
    ],
  },
  {
    category: 'Risky Functionality - Card Payment',
    items: [
      { t: 'Test for known vulnerabilities and configuration issues', auto: true },
      { t: 'Test for default or guessable password', auto: true },
      'Test for non-production data in live environment, and vice-versa',
      { t: 'Test for Injection vulnerabilities', auto: true },
      'Test for Buffer Overflows', 'Test for Insecure Cryptographic Storage',
      { t: 'Test for Insufficient Transport Layer Protection', auto: true },
      { t: 'Test for Improper Error Handling', auto: true },
      'Test for all vulnerabilities with a CVSS v2 score > 4.0',
      'Test for Authentication and Authorization issues',
      { t: 'Test for CSRF', auto: true },
    ],
  },
  {
    category: 'HTML 5',
    items: [
      'Test Web Messaging', 'Test for Web Storage SQL injection',
      { t: 'Check CORS implementation', auto: true },
      'Check Offline Web Application',
    ],
  },
];

function normalized() {
  return CHECKLIST.map((group) => ({
    category: group.category,
    items: group.items.map((it, idx) => {
      const text = typeof it === 'string' ? it : it.t;
      const auto = typeof it === 'string' ? false : !!it.auto;
      const id =
        group.category.toLowerCase().replace(/[^a-z0-9]+/g, '-') + '-' + idx;
      return { id, text, auto };
    }),
  }));
}

module.exports = { CHECKLIST, normalized, OWASP };
