import crypto from 'node:crypto';

// Haversine formula to compute great-circle distance in kilometers between two geo coordinates
export function calculateGeoDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371; // Earth's radius in km
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// Known brand domains for typosquatting / phishing detection
export const MONITORED_BRANDS = [
  'google', 'paypal', 'microsoft', 'apple', 'amazon', 'facebook',
  'netflix', 'chase', 'bankofamerica', 'wellsfargo', 'github',
  'linkedin', 'instagram', 'dropbox', 'coinbase', 'binance', 'stripe',
  'hdfc', 'sbi', 'icici', 'axisbank', 'paytm'
];

// High-risk TLDs often abused in phishing campaigns
export const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.work', '.click', '.buzz', '.zip', '.mov', '.surf',
  '.rest', '.monster', '.loan', '.gq', '.ml', '.cf', '.tk', '.ga', '.fit', '.cc'
];

// Known URL shortener services
export const KNOWN_URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly',
  'goo.gl', 'rb.gy', 'cutt.ly', 'shorturl.at', 'bl.ink', 'rebrand.ly'
];

// Calculate Shannon entropy of a string (useful for finding random DGA domains or encrypted payloads)
export function calculateShannonEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;
  const freq: Record<string, number> = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in freq) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

// Levenshtein distance for typosquatting
export function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

// ----------------------------------------------------------------------
// 1. SUSPICIOUS LOGIN DETECTION ENGINE (RULES 1 - 5)
// ----------------------------------------------------------------------

export interface UserHistoricalBaseline {
  totalLogins: number;
  knownCities: string[];
  knownCountries: string[];
  knownBrowsers: string[];
  knownOperatingSystems: string[];
  typicalHours: number[]; // e.g. [8, 9, 10, ... 20]
}

export interface SuspiciousLoginInput {
  userId: string;
  userEmail: string;
  ip: string;
  location: {
    city: string;
    country: string;
    lat: number;
    lon: number;
  };
  device: {
    browser: string;
    os: string;
    userAgent: string;
    isKnownDevice?: boolean;
  };
  // Detection Rule Context
  recentFailedAttemptsCount?: number; // Failures in detection window
  windowMinutes?: number;
  isSuccessfulLoginNow?: boolean; // True if this event represents a success
  hadRecentMultipleFailuresPrior?: boolean; // Rule 2: failures followed by success
  recentAttemptsRatePerMin?: number; // Rule 3: burst frequency
  historicalBaseline?: UserHistoricalBaseline; // Rule 4: compare with history
  headers?: Record<string, string>; // Rule 5: inspect unusual signals
  isTorOrVpn?: boolean;
  attemptHour?: number;
}

export interface RiskFactor {
  factor: string;
  penalty: number;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
  ruleReference: string;
}

export interface SuspiciousLoginResult {
  riskScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  detectionTime: string;
  action: 'ALLOW' | 'REQUIRE_MFA' | 'STEP_UP_BIOMETRIC' | 'TEMPORARY_LOCK' | 'HARD_BLOCK';
  recommendedAction: string;
  reasons: string[];
  factors: RiskFactor[];
  ruleEvaluation: {
    rule1_repeatedFailures: boolean;
    rule2_failuresFollowedBySuccess: boolean;
    rule3_unusuallyFrequentLogins: boolean;
    rule4_historicalAnomaly: boolean;
    rule5_unusualSignals: boolean;
  };
  relevantInfo: Record<string, any>;
  disclaimer: string;
}

export function evaluateSuspiciousLogin(
  input: SuspiciousLoginInput,
  settings: {
    failedLoginsThreshold: number; // default: 5
    failedLoginsWindowMinutes: number; // default: 5
    burstVelocityThresholdPerMinute: number; // default: 8
    mfaScoreThreshold: number; // default: 30
    blockScoreThreshold: number; // default: 70
    blockTorByDefault: boolean;
  }
): SuspiciousLoginResult {
  let score = 0;
  const factors: RiskFactor[] = [];
  const reasons: string[] = [];

  const ruleEvaluation = {
    rule1_repeatedFailures: false,
    rule2_failuresFollowedBySuccess: false,
    rule3_unusuallyFrequentLogins: false,
    rule4_historicalAnomaly: false,
    rule5_unusualSignals: false,
  };

  // ------------------------------------------------------------------
  // RULE 1: Repeated Failed Logins within Configurable Time Window
  // ------------------------------------------------------------------
  const failureCount = input.recentFailedAttemptsCount || 0;
  const threshold = settings.failedLoginsThreshold || 5;
  const windowMins = settings.failedLoginsWindowMinutes || 5;

  if (failureCount >= threshold) {
    ruleEvaluation.rule1_repeatedFailures = true;
    const penalty = Math.min(50, 30 + (failureCount - threshold) * 5);
    score += penalty;
    const desc = `${failureCount} failed login attempts recorded from ${input.ip} within ${windowMins} minutes (exceeds threshold of ${threshold}).`;
    reasons.push(desc);
    factors.push({
      factor: 'Rule 1: Repeated Failed Logins',
      penalty,
      description: desc,
      severity: 'HIGH',
      ruleReference: `Threshold: ${threshold} failures in ${windowMins}m`,
    });
  } else if (failureCount >= 2) {
    score += failureCount * 6;
    const desc = `${failureCount} consecutive incorrect password submissions observed.`;
    reasons.push(desc);
    factors.push({
      factor: 'Rule 1: Elevated Failure Count',
      penalty: failureCount * 6,
      description: desc,
      severity: 'MEDIUM',
      ruleReference: `Threshold: ${threshold} failures in ${windowMins}m`,
    });
  }

  // ------------------------------------------------------------------
  // RULE 2: Multiple Failures Followed by a Successful Login
  // ------------------------------------------------------------------
  if (input.isSuccessfulLoginNow && (input.hadRecentMultipleFailuresPrior || failureCount >= 3)) {
    ruleEvaluation.rule2_failuresFollowedBySuccess = true;
    const penalty = 35;
    score += penalty;
    const desc = `Credential Guessing Indicator: Account experienced repeated failures (${Math.max(failureCount, 3)}) immediately preceding this successful authentication.`;
    reasons.push(desc);
    factors.push({
      factor: 'Rule 2: Repeated Failures Prior to Success',
      penalty,
      description: desc,
      severity: 'HIGH',
      ruleReference: 'Multiple failures immediately before success pattern',
    });
  }

  // ------------------------------------------------------------------
  // RULE 3: Unusually Frequent Login Attempts (Burst Velocity)
  // ------------------------------------------------------------------
  const rate = input.recentAttemptsRatePerMin || 0;
  const burstThreshold = settings.burstVelocityThresholdPerMinute || 8;
  if (rate >= burstThreshold) {
    ruleEvaluation.rule3_unusuallyFrequentLogins = true;
    const penalty = 30;
    score += penalty;
    const desc = `Burst Velocity Anomaly: Attempt frequency of ${rate} requests/min exceeds standard rate ceiling (${burstThreshold}/min). Consistent with automated credential stuffing tool.`;
    reasons.push(desc);
    factors.push({
      factor: 'Rule 3: Unusually Frequent Logins (Burst)',
      penalty,
      description: desc,
      severity: 'HIGH',
      ruleReference: `Rate ceiling: ${burstThreshold} attempts/min`,
    });
  }

  // ------------------------------------------------------------------
  // RULE 4: Compare with Historical Activity Baseline (When Available)
  // ------------------------------------------------------------------
  if (input.historicalBaseline && input.historicalBaseline.totalLogins >= 3) {
    const history = input.historicalBaseline;
    const newCountry = !history.knownCountries.map((c) => c.toLowerCase()).includes(input.location.country.toLowerCase());
    const newCity = !history.knownCities.map((c) => c.toLowerCase()).includes(input.location.city.toLowerCase());
    const newBrowser = !history.knownBrowsers.map((b) => b.toLowerCase()).includes(input.device.browser.toLowerCase());

    if (newCountry) {
      ruleEvaluation.rule4_historicalAnomaly = true;
      score += 25;
      const desc = `Historical Geo Divergence: Login originates from ${input.location.country}, not present in user profile historical baseline (${history.knownCountries.join(', ')}).`;
      reasons.push(desc);
      factors.push({
        factor: 'Rule 4: Historical Baseline Geolocation Mismatch',
        penalty: 25,
        description: desc,
        severity: 'MEDIUM',
        ruleReference: `Compared against ${history.totalLogins} verified historical sessions`,
      });
    } else if (newCity) {
      score += 10;
      const desc = `New City of Origin: User logging in from ${input.location.city} for the first time.`;
      reasons.push(desc);
      factors.push({
        factor: 'Rule 4: Unseen City Origin',
        penalty: 10,
        description: desc,
        severity: 'LOW',
        ruleReference: `Known cities: ${history.knownCities.join(', ')}`,
      });
    }

    if (newBrowser) {
      score += 12;
      const desc = `New Client Application: User-Agent browser (${input.device.browser}) does not match previously observed user devices.`;
      reasons.push(desc);
      factors.push({
        factor: 'Rule 4: Novel Device / Browser Signature',
        penalty: 12,
        description: desc,
        severity: 'LOW',
        ruleReference: `Historical devices: ${history.knownBrowsers.join(', ')}`,
      });
    }
  }

  // ------------------------------------------------------------------
  // RULE 5: Identify Missing or Unusual Login Signals
  // ------------------------------------------------------------------
  const ua = (input.device.userAgent || '').toLowerCase();
  const headlessPatterns = ['headless', 'phantomjs', 'python', 'curl', 'wget', 'postman', 'httpclient', 'requests'];
  const isHeadlessOrScripted = headlessPatterns.some((p) => ua.includes(p));

  if (!input.device.userAgent || input.device.userAgent.trim() === '') {
    ruleEvaluation.rule5_unusualSignals = true;
    score += 20;
    const desc = 'Missing Signal: Request lacks standard HTTP User-Agent header commonly emitted by standard browsers.';
    reasons.push(desc);
    factors.push({
      factor: 'Rule 5: Missing User-Agent Header',
      penalty: 20,
      description: desc,
      severity: 'MEDIUM',
      ruleReference: 'Signal completeness validation',
    });
  } else if (isHeadlessOrScripted) {
    ruleEvaluation.rule5_unusualSignals = true;
    score += 25;
    const desc = `Automated Client Signature: User-Agent identifies as scripted or headless agent (${input.device.userAgent}).`;
    reasons.push(desc);
    factors.push({
      factor: 'Rule 5: Headless or Scripted User-Agent',
      penalty: 25,
      description: desc,
      severity: 'MEDIUM',
      ruleReference: 'Browser runtime heuristics',
    });
  }

  if (input.isTorOrVpn) {
    ruleEvaluation.rule5_unusualSignals = true;
    const penalty = settings.blockTorByDefault ? 35 : 20;
    score += penalty;
    const desc = `Anonymizer Signal: IP ${input.ip} resolves to an active Tor exit node or commercial privacy VPN tunnel.`;
    reasons.push(desc);
    factors.push({
      factor: 'Rule 5: Tor / VPN Anonymizer Network',
      penalty,
      description: desc,
      severity: settings.blockTorByDefault ? 'HIGH' : 'MEDIUM',
      ruleReference: 'Perimeter threat feed intelligence',
    });
  }

  // Cap score between 0 and 100
  const finalScore = Math.min(100, Math.max(0, score));

  // Risk Level according to user specification:
  // Low: 0–29 | Medium: 30–69 | High: 70–100
  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';
  let action: 'ALLOW' | 'REQUIRE_MFA' | 'STEP_UP_BIOMETRIC' | 'TEMPORARY_LOCK' | 'HARD_BLOCK' = 'ALLOW';
  let recommendedAction = 'Allow login with standard audit tracking.';

  if (finalScore >= 70) {
    riskLevel = 'HIGH';
    action = finalScore >= 85 ? 'HARD_BLOCK' : 'TEMPORARY_LOCK';
    recommendedAction =
      'Immediate Defense: Temporary session lock and enforce hardware token or biometric identity verification before unlocking account.';
  } else if (finalScore >= 30) {
    riskLevel = 'MEDIUM';
    action = 'REQUIRE_MFA';
    recommendedAction =
      'Step-up Defense: Challenge connection with mandatory Two-Factor Authentication (OTP or push approval).';
  } else {
    riskLevel = 'LOW';
    action = 'ALLOW';
    recommendedAction =
      'Normal Operation: Grant session and record event into standard telemetry stream.';
  }

  return {
    riskScore: finalScore,
    riskLevel,
    detectionTime: new Date().toISOString(),
    action,
    recommendedAction,
    reasons: reasons.length > 0 ? reasons : ['Session parameters conform to normal baseline criteria.'],
    factors,
    ruleEvaluation,
    relevantInfo: {
      ip: input.ip,
      location: `${input.location.city}, ${input.location.country}`,
      device: input.device.browser,
      failureCount,
      rate,
    },
    disclaimer:
      'NOTICE: Calculated risk scores are behavioral anomaly indicators and do not provide definitive legal proof of malicious intent. Signals may occasionally indicate legitimate users using VPNs or new devices.',
  };
}

// ----------------------------------------------------------------------
// 2. PHISHING CHECKER ENGINE (URL & MESSAGE ANALYSIS)
// ----------------------------------------------------------------------

export interface PhishingFinding {
  rule: string;
  points: number;
  detail: string;
  type: 'PASS' | 'WARN' | 'DANGER';
}

export interface PhishingUrlResult {
  type: 'URL';
  target: string;
  domain: string;
  riskScore: number; // 0-100
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  verdict: string;
  indicators: string[];
  findings: PhishingFinding[];
  entropy: number;
  isShortener: boolean;
  hasPunycodeHomograph: boolean;
  targetedBrand?: string;
  recommendedAction: string;
  disclaimer: string;
}

export interface PhishingMessageResult {
  type: 'MESSAGE';
  samplePreview: string; // Truncated preview
  riskScore: number; // 0-100
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  verdict: string;
  detectedCategories: {
    urgentCallToAction: boolean;
    credentialRequest: boolean;
    financialOrOtpRequest: boolean;
    unexpectedPrizeOrReward: boolean;
    fearOrAccountWarning: boolean;
    suspiciousLinksContained: string[];
  };
  matchedIndicators: string[];
  findings: PhishingFinding[];
  recommendedAction: string;
  disclaimer: string;
}

export function analyzePhishingUrl(rawUrl: string): PhishingUrlResult {
  let urlStr = rawUrl.trim();
  if (!/^https?:\/\//i.test(urlStr)) {
    urlStr = 'https://' + urlStr;
  }

  let parsed: URL;
  try {
    parsed = new URL(urlStr);
  } catch {
    return {
      type: 'URL',
      target: rawUrl,
      domain: 'invalid-url',
      riskScore: 90,
      riskLevel: 'HIGH',
      verdict: 'Malformed URL structure',
      indicators: ['Malformed or invalid RFC syntax', 'Unparseable hostname'],
      findings: [
        {
          rule: 'URL Syntax Structure',
          points: 90,
          detail: 'The provided string cannot be parsed as a standard RFC-compliant URL.',
          type: 'DANGER',
        },
      ],
      entropy: 0,
      isShortener: false,
      hasPunycodeHomograph: false,
      recommendedAction: 'Do not attempt to open this URL. Syntax is malformed and may be crafted for parser evasion.',
      disclaimer: 'Analysis is heuristic and educational. Absence of flags does not guarantee safety.',
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname.toLowerCase();
  let score = 0;
  const indicators: string[] = [];
  const findings: PhishingFinding[] = [];

  // 1. IP Address Hostname Check
  const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  if (isIpv4) {
    score += 40;
    indicators.push('Direct numeric IPv4 address used instead of domain name');
    findings.push({
      rule: 'Raw IP Hostname',
      points: 40,
      detail: `URL points to numerical IP ${hostname}. Standard commercial services utilize registered DNS names.`,
      type: 'DANGER',
    });
  } else {
    findings.push({
      rule: 'Raw IP Hostname',
      points: 0,
      detail: 'Standard registered domain name utilized.',
      type: 'PASS',
    });
  }

  // 2. URL Shortener Detection
  const isShortener = KNOWN_URL_SHORTENERS.includes(hostname);
  if (isShortener) {
    score += 25;
    indicators.push(`Known URL shortener service (${hostname}) disguising true destination`);
    findings.push({
      rule: 'URL Shortener Redirection',
      points: 25,
      detail: `Domain belongs to shortening provider ${hostname}, obscuring the ultimate target page.`,
      type: 'WARN',
    });
  }

  // 3. IDN Homograph / Punycode Check
  const isPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');
  const nonAscii = /[^\u0000-\u007F]/.test(parsed.hostname);
  const hasHomograph = isPunycode || nonAscii;
  if (hasHomograph) {
    score += 45;
    indicators.push('Internationalized Domain Name (IDN) homoglyph or punycode character spoofing');
    findings.push({
      rule: 'Lookalike Homoglyph Spoofing',
      points: 45,
      detail: 'Hostname employs internationalized character glyphs designed to visually imitate authentic brands.',
      type: 'DANGER',
    });
  }

  // 4. Unexpected URL Encoding (%2e%2e, double encoding)
  if (rawUrl.includes('%2e%2e') || rawUrl.includes('%25') || /%[0-9a-f]{2}.*%[0-9a-f]{2}/i.test(parsed.pathname)) {
    score += 30;
    indicators.push('Unexpected or double percent-encoding observed in URL path');
    findings.push({
      rule: 'URL Encoding Evasion',
      points: 30,
      detail: 'Path contains obfuscated or double-encoded hex byte sequences often used in path traversal attacks.',
      type: 'DANGER',
    });
  }

  // 5. Excessive Subdomains (Deep hierarchy >= 4 labels)
  const hostParts = hostname.split('.');
  if (hostParts.length >= 4) {
    score += 20;
    indicators.push(`Excessive subdomain hierarchy (${hostParts.length} levels)`);
    findings.push({
      rule: 'Excessive Subdomains',
      points: 20,
      detail: `Domain features ${hostParts.length} nested subdomain labels designed to push deceptive keywords into mobile viewports.`,
      type: 'WARN',
    });
  }

  // 6. Lookalike Brand Squatting & Typosquatting
  let targetedBrand: string | undefined;
  for (const brand of MONITORED_BRANDS) {
    const sld = hostParts.length >= 2 ? hostParts[hostParts.length - 2] : '';
    if (hostname.includes(brand)) {
      if (sld !== brand) {
        score += 40;
        targetedBrand = brand;
        indicators.push(`Brand Masquerade: Mentions "${brand}" but authoritative registrar differs`);
        findings.push({
          rule: 'Brand Squatting / Subdomain Masquerade',
          points: 40,
          detail: `The brand "${brand}" is placed in a subdomain or slug on an unrelated domain (${hostname}).`,
          type: 'DANGER',
        });
        break;
      }
    } else {
      const dist = levenshteinDistance(sld, brand);
      if (dist === 1 && sld.length >= 4) {
        score += 45;
        targetedBrand = brand;
        indicators.push(`Typosquatting: Domain "${sld}" is 1 letter away from "${brand}"`);
        findings.push({
          rule: 'Typosquatting Distance',
          points: 45,
          detail: `SLD "${sld}" is a 1-character permutation of recognized platform "${brand}".`,
          type: 'DANGER',
        });
        break;
      }
    }
  }

  // 7. High-Risk Abused TLD
  const hasBadTld = SUSPICIOUS_TLDS.some((tld) => hostname.endsWith(tld));
  if (hasBadTld) {
    score += 25;
    indicators.push('Domain utilizes high-abuse or disposable Top-Level Domain (TLD)');
    findings.push({
      rule: 'TLD Reputation',
      points: 25,
      detail: 'Top-level extension is statistically overrepresented in low-cost automated phishing campaigns.',
      type: 'WARN',
    });
  }

  // 8. Cleartext HTTP
  if (parsed.protocol === 'http:') {
    score += 15;
    indicators.push('Unencrypted Transport (Cleartext HTTP rather than HTTPS)');
    findings.push({
      rule: 'Transport Security',
      points: 15,
      detail: 'Connection does not enforce TLS encryption, exposing transmitted credentials to eavesdropping.',
      type: 'WARN',
    });
  } else {
    findings.push({
      rule: 'Transport Security',
      points: 0,
      detail: 'HTTPS protocol is specified.',
      type: 'PASS',
    });
  }

  // 9. Shannon Entropy
  const domainEntropy = calculateShannonEntropy(hostname);
  if (domainEntropy > 3.8 && hostname.length > 14) {
    score += 20;
    indicators.push(`High Shannon Entropy (${domainEntropy} bits): Statistical randomness consistent with DGA`);
    findings.push({
      rule: 'Domain Entropy (DGA)',
      points: 20,
      detail: `Hostname exhibits high randomness (${domainEntropy} bits), typical of Domain Generation Algorithms.`,
      type: 'WARN',
    });
  }

  const finalScore = Math.min(100, score);
  // Risk Level: Low (0-29), Medium (30-69), High (70-100)
  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';
  let verdict = 'No suspicious domain patterns flagged. Proceed with general browsing hygiene.';
  let recommendedAction = 'Standard caution. Inspect browser address bar before entering credentials.';

  if (finalScore >= 70) {
    riskLevel = 'HIGH';
    verdict = 'High-Risk Phishing / Fraud Indicator: Multiple severe deceptive patterns detected.';
    recommendedAction = 'DO NOT open this link. Do not submit login passwords, OTPs, or financial details.';
  } else if (finalScore >= 30) {
    riskLevel = 'MEDIUM';
    verdict = 'Elevated Risk: Several suspicious domain or protocol characteristics detected.';
    recommendedAction = 'Exercise extreme caution. Verify the sender channel and check the destination domain carefully.';
  }

  return {
    type: 'URL',
    target: rawUrl,
    domain: hostname,
    riskScore: finalScore,
    riskLevel,
    verdict,
    indicators,
    findings,
    entropy: domainEntropy,
    isShortener,
    hasPunycodeHomograph: hasHomograph,
    targetedBrand,
    recommendedAction,
    disclaimer:
      'Important Security Notice: This analysis uses transparent heuristic rules for defensive education. An absence of suspicious indicators does NOT guarantee a URL is safe. Never automatically click links from untrusted communications.',
  };
}

export function analyzePhishingMessage(rawText: string): PhishingMessageResult {
  const text = rawText.trim();
  const lower = text.toLowerCase();
  let score = 0;
  const matchedIndicators: string[] = [];
  const findings: PhishingFinding[] = [];

  const detectedCategories = {
    urgentCallToAction: false,
    credentialRequest: false,
    financialOrOtpRequest: false,
    unexpectedPrizeOrReward: false,
    fearOrAccountWarning: false,
    suspiciousLinksContained: [] as string[],
  };

  // 1. Urgent Call to Action / Pressure Tactics
  const urgencyPatterns = [
    'immediate action required', 'act immediately', 'act now', 'within 24 hours',
    'within 12 hours', 'within 1 hour', 'account will be suspended', 'account will be terminated',
    'urgent notice', 'final warning', 'immediate response', 'respond immediately', 'do not ignore'
  ];
  const matchedUrgency = urgencyPatterns.filter((p) => lower.includes(p));
  if (matchedUrgency.length > 0) {
    detectedCategories.urgentCallToAction = true;
    const pts = Math.min(30, 20 + (matchedUrgency.length - 1) * 5);
    score += pts;
    matchedIndicators.push(`Urgency / Psychological Pressure: "${matchedUrgency.join('", "')}"`);
    findings.push({
      rule: 'Urgency & Coercive Pressure',
      points: pts,
      detail: `Contains high-pressure phrases designed to induce hasty compliance (${matchedUrgency.join(', ')}).`,
      type: 'DANGER',
    });
  }

  // 2. Request for Passwords, PINs, OTPs or Credentials
  const credentialPatterns = [
    'enter your password', 'verify your password', 'confirm password', 'send otp',
    'share otp', 'enter otp', 'provide your pin', 'debit card pin', 'credit card pin',
    'cvv', 'secret key', 'seed phrase', 'identity verification', 'submit credentials'
  ];
  const matchedCreds = credentialPatterns.filter((p) => lower.includes(p));
  if (matchedCreds.length > 0) {
    detectedCategories.credentialRequest = true;
    const pts = 40;
    score += pts;
    matchedIndicators.push(`Explicit Request for Secrets: "${matchedCreds.join('", "')}"`);
    findings.push({
      rule: 'Credential / Secret Exfiltration',
      points: pts,
      detail: `Message explicitly prompts the recipient to share passwords, OTPs, or cryptographic keys. Legitimate organizations never request secret codes via message.`,
      type: 'DANGER',
    });
  }

  // 3. Financial, Banking, or Account Warnings
  const bankingWarningPatterns = [
    'unauthorized transaction', 'suspicious sign-in', 'unauthorized debit',
    'account locked', 'account frozen', 'kyc verification', 'kyc pending',
    'update kyc', 'pan card update', 'bank account blocked', 'tax refund'
  ];
  const matchedBank = bankingWarningPatterns.filter((p) => lower.includes(p));
  if (matchedBank.length > 0) {
    detectedCategories.fearOrAccountWarning = true;
    const pts = 25;
    score += pts;
    matchedIndicators.push(`Account Fear / Security Alert Lure: "${matchedBank.join('", "')}"`);
    findings.push({
      rule: 'Pretexting & Fear Appeal',
      points: pts,
      detail: `Employs security breach, debit alert, or KYC suspension pretexts (${matchedBank.join(', ')}).`,
      type: 'WARN',
    });
  }

  // 4. Unexpected Prizes, Lottery, Cash Reward Lures
  const prizePatterns = [
    'congratulations you won', 'lottery winner', 'cash prize', 'exclusive bonus',
    'selected for a reward', 'claim your prize', 'free gift card', '10,000 bonus'
  ];
  const matchedPrize = prizePatterns.filter((p) => lower.includes(p));
  if (matchedPrize.length > 0) {
    detectedCategories.unexpectedPrizeOrReward = true;
    const pts = 30;
    score += pts;
    matchedIndicators.push(`Unsolicited Reward Lure: "${matchedPrize.join('", "')}"`);
    findings.push({
      rule: 'Greed / Bait Lure',
      points: pts,
      detail: `Message lures recipient with unsolicited monetary prizes or gift rewards.`,
      type: 'DANGER',
    });
  }

  // 5. Embedded Links Check
  const urlRegex = /(https?:\/\/[^\s]+|bit\.ly\/[^\s]+|tinyurl\.com\/[^\s]+|t\.co\/[^\s]+)/gi;
  const foundUrls = text.match(urlRegex) || [];
  if (foundUrls.length > 0) {
    detectedCategories.suspiciousLinksContained = foundUrls.slice(0, 3);
    score += 15;
    matchedIndicators.push(`Embedded Hyperlinks: Found ${foundUrls.length} link(s) in message body`);
    findings.push({
      rule: 'Embedded External Hyperlink',
      points: 15,
      detail: `Contains actionable web link(s) within the message text.`,
      type: 'WARN',
    });
  }

  const finalScore = Math.min(100, score);
  // Risk Level: Low (0-29), Medium (30-69), High (70-100)
  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';
  let verdict = 'Message does not display typical social engineering keywords.';
  let recommendedAction = 'Exercise normal caution. Do not forward unverified messages.';

  if (finalScore >= 70) {
    riskLevel = 'HIGH';
    verdict = 'High-Confidence Social Engineering / Phishing Pretext Detected.';
    recommendedAction =
      'DEFENSIVE ACTION: Do NOT reply, do not click embedded links, and NEVER share OTPs or passwords. Report the communication as phishing.';
  } else if (finalScore >= 30) {
    riskLevel = 'MEDIUM';
    verdict = 'Suspicious Indicators Found: Employs urgency or unprompted warning language.';
    recommendedAction =
      'Verify through an independent, official channel (e.g. dial the customer care number on the back of your bank card).';
  }

  return {
    type: 'MESSAGE',
    samplePreview: text.length > 80 ? text.slice(0, 80) + '...' : text,
    riskScore: finalScore,
    riskLevel,
    verdict,
    detectedCategories,
    matchedIndicators,
    findings,
    recommendedAction,
    disclaimer:
      'Disclaimer: Rule-based text inspection is designed for defensive education and can produce false positives or false negatives. Never use an automated score alone as definitive proof. Never share passwords or OTPs under any circumstances.',
  };
}

// ----------------------------------------------------------------------
// 3. DIGITAL PAYMENT RISK ANALYZER (SYNTHETIC TRANSACTIONS ONLY)
// ----------------------------------------------------------------------

export interface PaymentTransactionRecord {
  transactionId: string;
  accountRef: string;
  amount: number;
  timestamp: string; // ISO string
  paymentMethod: 'UPI' | 'CREDIT_CARD' | 'DEBIT_CARD' | 'NET_BANKING' | 'WALLET';
  transactionResult: 'SUCCESS' | 'FAILED' | 'PENDING';
  merchantCategory: 'ELECTRONICS' | 'GROCERY' | 'TRAVEL' | 'GAMING' | 'UTILITIES';
  riskScore?: number;
  riskLevel?: 'LOW' | 'MEDIUM' | 'HIGH';
  reasons?: string[];
  triggeredRules?: string[];
  isSynthetic: boolean;
}

export function evaluatePaymentTransactions(
  transactions: PaymentTransactionRecord[],
  baselineAmount: number = 500
): PaymentTransactionRecord[] {
  // Track seen IDs for duplicate detection
  const idCounts = new Map<string, number>();
  for (const t of transactions) {
    const id = t.transactionId.trim();
    idCounts.set(id, (idCounts.get(id) || 0) + 1);
  }

  // Group by accountRef to detect velocity and rapid succession
  const byAccount = new Map<string, PaymentTransactionRecord[]>();
  for (const t of transactions) {
    const acc = t.accountRef.trim();
    if (!byAccount.has(acc)) byAccount.set(acc, []);
    byAccount.get(acc)!.push(t);
  }

  return transactions.map((t) => {
    let score = 0;
    const reasons: string[] = [];
    const triggeredRules: string[] = [];

    // Rule 1: Duplicate Transaction Identifier
    if ((idCounts.get(t.transactionId.trim()) || 0) > 1) {
      score += 45;
      triggeredRules.push('RULE_1_DUPLICATE_TRANSACTION_ID');
      reasons.push(`Duplicate Identifier: Transaction ID ${t.transactionId} appears multiple times in batch.`);
    }

    // Rule 2: Unusually High Amount Compared to Baseline
    const ratio = baselineAmount > 0 ? t.amount / baselineAmount : 1;
    if (ratio >= 6 && t.amount >= 3000) {
      score += 40;
      triggeredRules.push('RULE_2_EXTREME_AMOUNT_DEVIATION');
      reasons.push(`Extreme Amount: Amount ($${t.amount}) is ${ratio.toFixed(1)}x greater than baseline ($${baselineAmount}).`);
    } else if (ratio >= 3 && t.amount >= 1500) {
      score += 25;
      triggeredRules.push('RULE_2_ELEVATED_AMOUNT');
      reasons.push(`Elevated Amount: Amount ($${t.amount}) is ${ratio.toFixed(1)}x baseline.`);
    }

    // Account history context
    const accountTxns = byAccount.get(t.accountRef.trim()) || [];
    const currentTime = new Date(t.timestamp).getTime();

    // Rule 3: Repeated Transactions within Short Period (<= 5 minutes)
    const closeTxns = accountTxns.filter((other) => {
      if (other.transactionId === t.transactionId) return false;
      const otherTime = new Date(other.timestamp).getTime();
      const diffMs = Math.abs(currentTime - otherTime);
      return diffMs <= 5 * 60 * 1000;
    });

    if (closeTxns.length > 0) {
      score += 30;
      triggeredRules.push('RULE_3_REPEATED_WITHIN_5_MINUTES');
      reasons.push(`Rapid Repetition: ${closeTxns.length + 1} transactions executed within 5 minutes on account ${t.accountRef}.`);
    }

    // Rule 4: Unusual Transaction Frequency (Velocity Burst)
    if (accountTxns.length >= 4) {
      score += 25;
      triggeredRules.push('RULE_4_HIGH_TRANSACTION_FREQUENCY');
      reasons.push(`High Velocity: Account ${t.accountRef} generated ${accountTxns.length} transactions in batch window.`);
    }

    // Rule 5: Multiple Failed Transactions
    const failedOnAccount = accountTxns.filter((other) => other.transactionResult === 'FAILED');
    if (t.transactionResult === 'FAILED') {
      score += 15;
      triggeredRules.push('RULE_5_FAILED_TRANSACTION');
      reasons.push('Execution Failure: Payment gateway returned non-success result.');
    } else if (failedOnAccount.length >= 2) {
      score += 30;
      triggeredRules.push('RULE_5_CARD_TESTING_FAILURES');
      reasons.push(`Preceding Failures: Account experienced ${failedOnAccount.length} failures before this attempt (card testing pattern).`);
    }

    // Rule 6: Duplicate-Looking Records (same account, same amount, same merchant category)
    const duplicateLooking = accountTxns.filter(
      (other) =>
        other.transactionId !== t.transactionId &&
        other.amount === t.amount &&
        other.merchantCategory === t.merchantCategory
    );
    if (duplicateLooking.length > 0) {
      score += 35;
      triggeredRules.push('RULE_6_DUPLICATE_CHARGE_SUSPECT');
      reasons.push(`Duplicate Charge Suspect: Identical amount ($${t.amount}) and merchant (${t.merchantCategory}) matched.`);
    }

    const finalScore = Math.min(100, score);
    // Risk Level: Low (0-29), Medium (30-69), High (70-100)
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';
    if (finalScore >= 70) {
      riskLevel = 'HIGH';
    } else if (finalScore >= 30) {
      riskLevel = 'MEDIUM';
    }

    return {
      ...t,
      riskScore: finalScore,
      riskLevel,
      reasons: reasons.length > 0 ? reasons : ['Transaction metrics conform to expected baseline parameters.'],
      triggeredRules,
      isSynthetic: true,
    };
  });
}

// ----------------------------------------------------------------------
// 4. CRYPTOGRAPHIC FILE INTEGRITY HASHER
// ----------------------------------------------------------------------

export function computeFileHashes(content: string | Buffer): {
  sha256: string;
  sha512: string;
  md5: string;
  sizeBytes: number;
  entropy: number;
} {
  const buffer = typeof content === 'string' ? Buffer.from(content, 'utf-8') : content;
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  const sha512 = crypto.createHash('sha512').update(buffer).digest('hex');
  const md5 = crypto.createHash('md5').update(buffer).digest('hex');

  const len = buffer.length;
  let entropy = 0;
  if (len > 0) {
    const freq = new Array(256).fill(0);
    for (let i = 0; i < len; i++) {
      freq[buffer[i]]++;
    }
    for (let i = 0; i < 256; i++) {
      if (freq[i] > 0) {
        const p = freq[i] / len;
        entropy -= p * Math.log2(p);
      }
    }
  }

  return {
    sha256,
    sha512,
    md5,
    sizeBytes: len,
    entropy: Number(entropy.toFixed(3)),
  };
}
