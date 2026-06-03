/**
 * Rule-based scam detection engine
 * Analyzes text for common scam patterns, email headers, and URL reputation
 */

const SCAM_PATTERNS = [
  // Financial/money scams
  { pattern: /win\s+(money|prize|cash|jackpot|lottery)/gi, risk: 'high', keyword: 'Win money' },
  { pattern: /claim\s+(your\s+)?reward/gi, risk: 'high', keyword: 'Claim reward' },
  { pattern: /verify\s+(your\s+)?(account|identity|payment)/gi, risk: 'high', keyword: 'Verify account' },
  { pattern: /confirm\s+(your\s+)?(password|pin|banking|details)/gi, risk: 'high', keyword: 'Confirm details' },
  { pattern: /bank\s+(details|account|information|credentials)/gi, risk: 'critical', keyword: 'Bank details requested' },
  { pattern: /credit\s+card\s+(number|details|information)/gi, risk: 'critical', keyword: 'Credit card info' },
  { pattern: /ssn|social\s+security\s+number/gi, risk: 'critical', keyword: 'SSN requested' },
  { pattern: /wire\s+transfer|western\s+union|money\s+transfer|bitcoin|cryptocurrency|crypto\s+wallet|ethereum/gi, risk: 'high', keyword: 'Money transfer/crypto request' },
  { pattern: /investment\s+opportunity|double\s+your\s+money|easy\s+profits/gi, risk: 'high', keyword: 'Too-good-to-be-true investment' },
  { pattern: /notary\s+public|official\s+notice|final\s+notice|account\s+closure|service\s+termination|security\s+update/gi, risk: 'medium', keyword: 'Official-sounding pressure' },

  // Urgency/pressure tactics
  { pattern: /urgent|immediately|asap|act\s+now|limited\s+time/gi, risk: 'medium', keyword: 'Urgency pressure' },
  { pattern: /click\s+here|click\s+link|download\s+(now|here)/gi, risk: 'high', keyword: 'Suspicious link' },
  { pattern: /do\s+not\s+(share|tell|give|send).*password|never\s+ask/gi, risk: 'medium', keyword: 'Password warning' },

  // Impersonation
  { pattern: /from\s+(apple|amazon|google|microsoft|paypal|bank|irs|federal|government)/gi, risk: 'high', keyword: 'Brand impersonation' },
  { pattern: /account\s+(suspended|locked|disabled|compromised)/gi, risk: 'high', keyword: 'Account warning' },

  // Too good to be true
  { pattern: /free\s+(money|cash|iphone|gift)/gi, risk: 'high', keyword: 'Free money offer' },
  { pattern: /no\s+work|no\s+experience|easy\s+money/gi, risk: 'high', keyword: 'Easy money promise' },
  { pattern: /congratulations|you\s+have\s+been\s+selected/gi, risk: 'medium', keyword: 'Congratulations' },

  // Phishing/malware
  { pattern: /re-activate|reactivate|update\s+(payment|billing|profile)/gi, risk: 'high', keyword: 'Reactivation request' },
  { pattern: /unusual\s+(activity|login|transaction)/gi, risk: 'medium', keyword: 'Unusual activity' },
  { pattern: /suspicious\s+(activity|login)|unauthorized\s+(access|transaction)/gi, risk: 'medium', keyword: 'Security alert' },

  // Romance/advance fee scams
  { pattern: /i\s+love\s+you|darling|sweetheart|dear\s+(friend|one)/gi, risk: 'high', keyword: 'Romance scam language' },
  { pattern: /send\s+(money|payment|wire|funds)/gi, risk: 'high', keyword: 'Money transfer request' },

  // Generic red flags
  { pattern: /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}(?=.*password|confirm|verify|click)/gi, risk: 'medium', keyword: 'Email with suspicious action' },
]

const SAFE_INDICATORS = [
  /^from:\s*support@/i,
  /unsubscribe\s+link/i,
  /privacy\s+policy/i,
  /this\s+is\s+an\s+automated\s+message/i,
  /dear\s+customer/i,
]

export async function analyzeScam({ text = '', headers = '' } = {}) {
  const contentResult = analyzeTextSync(text)
  const headerResult = analyzeHeaders(headers)

  const urls = extractUrls(text)
  const urlReputation = await fetchUrlReputation(urls)

  const combinedMatches = [...contentResult.matches, ...headerResult.matches]
  const combinedRiskScore = Math.min(
    100,
    contentResult.riskScore + headerResult.extraRiskScore + (urlReputation.totalRisk || 0)
  )

  const riskLevel = determineRiskLevel(combinedRiskScore)
  const message = generateMessage(riskLevel, combinedMatches.length, combinedRiskScore >= 50)

  return {
    ...contentResult,
    ...headerResult,
    urlAnalysis: urlReputation,
    matches: combinedMatches.slice(0, 12),
    riskScore: combinedRiskScore,
    riskLevel,
    message,
  }
}

export function analyzeText(text) {
  return analyzeTextSync(text)
}

function analyzeTextSync(text) {
  if (!text || text.trim().length === 0) {
    return {
      isScam: false,
      riskScore: 0,
      riskLevel: 'unknown',
      message: 'Please enter text to analyze.',
      matches: [],
    }
  }

  const matches = []
  let totalRiskScore = 0

  // Find all pattern matches
  for (const patternObj of SCAM_PATTERNS) {
    const regex = patternObj.pattern
    let match
    while ((match = regex.exec(text)) !== null) {
      matches.push({
        keyword: patternObj.keyword,
        risk: patternObj.risk,
        text: match[0],
        index: match.index,
      })
      totalRiskScore += getRiskScore(patternObj.risk)
    }
  }

  // Analyze URLs in the text for common phishing indicators
  const urlAnalysis = analyzeURLs(text)
  for (const u of urlAnalysis.matches) {
    matches.push(u)
    totalRiskScore += getRiskScore(u.risk)
  }

  // Check for safe indicators
  let hasSafeIndicators = false
  for (const safePattern of SAFE_INDICATORS) {
    if (safePattern.test(text)) {
      hasSafeIndicators = true
      totalRiskScore = Math.max(0, totalRiskScore - 10)
      break
    }
  }

  const heuristicBonus = computeHeuristicScore(matches, hasSafeIndicators)
  totalRiskScore += heuristicBonus

  // Normalize risk score to 0-100
  const riskScore = Math.min(100, Math.round(totalRiskScore))

  // Determine risk level
  let riskLevel = 'safe'
  let isScam = false
  if (riskScore >= 70) {
    riskLevel = 'critical'
    isScam = true
  } else if (riskScore >= 50) {
    riskLevel = 'high'
    isScam = true
  } else if (riskScore >= 30) {
    riskLevel = 'medium'
  } else if (riskScore > 0) {
    riskLevel = 'low'
  }

  // Generate message
  const message = generateMessage(riskLevel, matches.length, isScam)

  return {
    isScam,
    riskScore,
    riskLevel,
    message,
    matches: matches.slice(0, 10), // Top 10 matches
  }
}

function analyzeHeaders(headers) {
  const trimmed = (headers || '').trim()
  if (!trimmed) {
    return {
      headerSummary: 'No headers provided.',
      headerIssues: [],
      extraRiskScore: 0,
      matches: [],
      parsedHeaders: null,
    }
  }

  const lines = trimmed.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
  const parsed = {}
  const issues = []
  const matches = []
  let extraRiskScore = 0

  for (const line of lines) {
    if (/^from:/i.test(line)) {
      parsed.from = line.replace(/^from:\s*/i, '').trim()
    }
    if (/^to:/i.test(line)) {
      parsed.to = line.replace(/^to:\s*/i, '').trim()
    }
    if (/^subject:/i.test(line)) {
      parsed.subject = line.replace(/^subject:\s*/i, '').trim()
    }
    if (/^authentication-results:/i.test(line)) {
      const status = parseAuthenticationResults(line)
      Object.assign(parsed, status.parsed)
      if (status.issues.length) {
        issues.push(...status.issues)
      }
    }
    if (/^received-spf:/i.test(line)) {
      const value = line.replace(/^received-spf:\s*/i, '').trim()
      parsed.spf = value
      if (/fail|softfail|neutral|none/i.test(value)) {
        issues.push(`SPF result: ${value}`)
      }
    }
    if (/^dkim-signature:/i.test(line)) {
      parsed.dkimSignature = true
    }
    if (/^dmarc-/i.test(line) || /^policy:\s*dmarc/i.test(line)) {
      parsed.dmarc = parsed.dmarc || 'present'
    }
    if (/^return-path:/i.test(line)) {
      const address = line.replace(/^return-path:\s*/i, '').trim()
      parsed.returnPath = address
      if (/\.ru|\.cn|\.top|\.xyz/i.test(address)) {
        issues.push(`Return-Path uses suspicious domain: ${address}`)
      }
    }
    if (/^received:/i.test(line) && /\[\d{1,3}(?:\.\d{1,3}){3}\]/.test(line)) {
      matches.push({ keyword: 'Received header with IP', risk: 'medium', text: line, index: 0 })
      extraRiskScore += getRiskScore('medium')
    }
  }

  if (!parsed.spf && !parsed.dkimSignature && !parsed.dmarc) {
    issues.push('No SPF/DKIM/DMARC authentication headers detected.')
    extraRiskScore += 8
  }

  if (issues.length > 0) {
    matches.push(...issues.map((issue) => ({ keyword: 'Header warning', risk: 'medium', text: issue, index: 0 })))
  }

  return {
    headerSummary: issues.length ? `Header warnings found (${issues.length})` : 'Email headers look normal.',
    headerIssues: issues,
    extraRiskScore,
    matches,
    parsedHeaders: parsed,
  }
}

function parseAuthenticationResults(line) {
  const parsed = {}
  const issues = []
  const lower = line.toLowerCase()

  const spfMatch = lower.match(/spf=(pass|fail|softfail|neutral|none)/)
  if (spfMatch) {
    parsed.spf = spfMatch[1]
    if (spfMatch[1] !== 'pass') {
      issues.push(`SPF result is ${spfMatch[1]}`)
    }
  }

  const dkimMatch = lower.match(/dkim=(pass|fail|neutral|none)/)
  if (dkimMatch) {
    parsed.dkim = dkimMatch[1]
    if (dkimMatch[1] !== 'pass') {
      issues.push(`DKIM result is ${dkimMatch[1]}`)
    }
  }

  const dmarcMatch = lower.match(/dmarc=(pass|fail|quarantine|reject|none)/)
  if (dmarcMatch) {
    parsed.dmarc = dmarcMatch[1]
    if (dmarcMatch[1] !== 'pass') {
      issues.push(`DMARC result is ${dmarcMatch[1]}`)
    }
  }

  if (/authentication-results:.*from\s+\S+\s+;.*spf=fail/i.test(line)) {
    issues.push('Authentication-Results indicates SPF failure for the sending domain.')
  }

  return { parsed, issues }
}

function extractUrls(text) {
  const URL_REGEX = /https?:\/\/[^\s<>"']+|www\.[^\s<>"']+/gi
  const urls = []
  let m
  while ((m = URL_REGEX.exec(text)) !== null) {
    urls.push(m[0])
  }
  return urls
}

async function fetchUrlReputation(urls) {
  if (!urls.length) {
    return { urls: [], totalRisk: 0, summary: 'No URLs found.' }
  }

  try {
    const response = await fetch('/api/url-reputation', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ urls }),
    })

    const data = await response.json()
    if (!response.ok) {
      return {
        urls: urls.map((url) => ({ url, status: 'error', note: data?.message || 'URL reputation service unavailable.' })),
        totalRisk: 0,
        summary: data?.message || 'URL reputation service unavailable.',
      }
    }

    return data
  } catch (error) {
    return {
      urls: urls.map((url) => ({ url, status: 'error', note: error.message })),
      totalRisk: 0,
      summary: 'Unable to reach URL reputation service.',
    }
  }
}

function analyzeURLs(text) {
  const URL_REGEX = /https?:\/\/[\w\-\.%:@\/\?=&#]+|www\.[\w\-\.%:@\/\?=&#]+/gi
  const SHORTENERS = /(bit\.ly|tinyurl\.com|t\.co|goo\.gl|owly\.co|buff\.ly)/i
  const SUSPICIOUS_TLDS = /\.(xyz|top|online|club|pw|info|ru)\b/i
  const matches = []
  let m
  while ((m = URL_REGEX.exec(text)) !== null) {
    const url = m[0]
    const idx = m.index
    if (/https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/.test(url)) {
      matches.push({ keyword: 'URL with IP', risk: 'high', text: url, index: idx })
    } else if (SHORTENERS.test(url)) {
      matches.push({ keyword: 'Shortened URL', risk: 'high', text: url, index: idx })
    } else if (SUSPICIOUS_TLDS.test(url)) {
      matches.push({ keyword: 'Suspicious TLD', risk: 'medium', text: url, index: idx })
    }
  }
  return { matches }
}

function getRiskScore(riskLevel) {
  const scores = {
    critical: 25,
    high: 15,
    medium: 8,
    low: 3,
  }
  return scores[riskLevel] || 0
}

function computeHeuristicScore(matches, hasSafeIndicators) {
  let score = 0
  for (const match of matches) {
    score += getRiskScore(match.risk) * (match.risk === 'critical' ? 1.1 : 1)
  }
  if (hasSafeIndicators) score = Math.max(0, score - 5)
  return Math.round(score * 0.15)
}

function determineRiskLevel(riskScore) {
  if (riskScore >= 70) return 'critical'
  if (riskScore >= 50) return 'high'
  if (riskScore >= 30) return 'medium'
  if (riskScore > 0) return 'low'
  return 'safe'
}

function generateMessage(riskLevel, matchCount, isScam) {
  const messages = {
    safe: 'This message appears to be safe. No suspicious patterns detected.',
    low: `This message has some minor warnings. ${matchCount} suspicious patterns detected. Use caution.`,
    medium: `⚠️ This message shows moderate red flags. ${matchCount} suspicious patterns detected. Be cautious before interacting.`,
    high: `🚨 High likelihood of scam. ${matchCount} suspicious patterns detected. Do not click links or provide personal information.`,
    critical: `🚨 CRITICAL: This is very likely a scam. ${matchCount} suspicious patterns detected. Do not engage. Report if received.`,
    unknown: 'Please enter text to analyze.',
  }
  return messages[riskLevel] || messages.safe
}

export function highlightSuspiciousWords(text, matches) {
  if (matches.length === 0) return text

  // Sort matches by index in reverse to maintain indices
  const sortedMatches = [...matches].sort((a, b) => b.index - a.index)

  let result = text
  for (const match of sortedMatches) {
    const startIdx = match.index
    const endIdx = startIdx + match.text.length
    const before = result.substring(0, startIdx)
    const after = result.substring(endIdx)
    const highlighted = `<mark class="bg-yellow-300 font-semibold">${match.text}</mark>`
    result = before + highlighted + after
  }

  return result
}
