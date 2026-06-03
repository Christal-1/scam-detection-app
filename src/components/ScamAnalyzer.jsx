import React, { useState } from 'react'
import { analyzeScam } from '../utils/scamDetector'

const sampleCases = [
  {
    label: 'Phishing email example',
    text: `Your account has been suspended. Click the link below to verify your information immediately or your access will be revoked.\nhttps://bit.ly/fake-login`,
    headers: `From: support@example.com\nTo: user@example.com\nSubject: Account verification required\nAuthentication-Results: spf=fail; dkim=fail; dmarc=fail;`,
  },
  {
    label: 'Urgent payment scam',
    text: `Payment failed. Please update your billing details using this secure link now: https://example.xyz/payment`,
    headers: `From: billing@payment-service.com\nTo: user@example.com\nSubject: Billing update required\nReceived-SPF: fail`,
  },
  {
    label: 'Safe message sample',
    text: `Hello, your subscription has been renewed successfully. If you need help, visit our official support page or reply to this email.`,
    headers: `From: support@official-service.com\nTo: user@example.com\nSubject: Subscription renewed\nAuthentication-Results: spf=pass; dkim=pass; dmarc=pass;`,
  },
]

export default function ScamAnalyzer() {
  const [inputText, setInputText] = useState('')
  const [headerText, setHeaderText] = useState('')
  const [result, setResult] = useState(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)

  async function handleAnalyze() {
    if (!inputText.trim() && !headerText.trim()) {
      setResult(null)
      return
    }

    setIsAnalyzing(true)
    try {
      const analysisResult = await analyzeScam({ text: inputText, headers: headerText })
      setResult(analysisResult)
    } catch (error) {
      setResult({
        isScam: false,
        riskScore: 0,
        riskLevel: 'unknown',
        message: `Unable to analyze content: ${error.message}`,
        matches: [],
        urlAnalysis: { urls: [], totalRisk: 0, summary: 'URL reputation unavailable.' },
        headerSummary: 'Header analysis unavailable.',
        headerIssues: [],
      })
    } finally {
      setIsAnalyzing(false)
    }
  }

  function handleClear() {
    setInputText('')
    setHeaderText('')
    setResult(null)
  }

  function handleSample(sample) {
    setInputText(sample.text)
    setHeaderText(sample.headers)
    setResult(null)
  }

  function getRiskColor(riskLevel) {
    const colors = {
      safe: 'bg-green-50 border-green-200 text-green-900',
      low: 'bg-blue-50 border-blue-200 text-blue-900',
      medium: 'bg-yellow-50 border-yellow-200 text-yellow-900',
      high: 'bg-orange-50 border-orange-200 text-orange-900',
      critical: 'bg-red-50 border-red-200 text-red-900',
      unknown: 'bg-gray-50 border-gray-200 text-gray-900',
    }
    return colors[riskLevel] || colors.unknown
  }

  function getRiskBadgeColor(riskLevel) {
    const colors = {
      safe: 'bg-green-100 text-green-800',
      low: 'bg-blue-100 text-blue-800',
      medium: 'bg-yellow-100 text-yellow-800',
      high: 'bg-orange-100 text-orange-800',
      critical: 'bg-red-100 text-red-800',
    }
    return colors[riskLevel] || 'bg-gray-100 text-gray-800'
  }

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h3 className="text-base font-semibold text-slate-900">Sample test cases</h3>
            <p className="text-sm text-slate-600">Load a sample to test the scanner quickly.</p>
          </div>
          <div className="flex flex-col gap-2 sm:flex-row">
            {sampleCases.map((sample) => (
              <button
                key={sample.label}
                type="button"
                onClick={() => handleSample(sample)}
                className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-700 hover:border-blue-500 hover:text-blue-700 transition"
              >
                {sample.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div>
        <label htmlFor="message-input" className="block text-sm font-medium text-gray-700 mb-2">
          Paste your message, email body, or text:
        </label>
        <textarea
          id="message-input"
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          placeholder="Paste suspicious message, email body, SMS, or text here..."
          className="w-full h-36 p-4 border-2 border-gray-300 rounded-lg font-mono text-sm focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-200 resize-none"
          onKeyDown={(e) => {
            if (e.key === 'Enter' && e.ctrlKey) {
              handleAnalyze()
            }
          }}
        />
        <p className="text-xs text-gray-500 mt-2">Tip: Use Ctrl+Enter to analyze</p>
      </div>

      <div>
        <label htmlFor="headers-input" className="block text-sm font-medium text-gray-700 mb-2">
          Paste email headers (optional):
        </label>
        <textarea
          id="headers-input"
          value={headerText}
          onChange={(e) => setHeaderText(e.target.value)}
          placeholder="Paste raw email headers here to detect SPF/DKIM/DMARC issues..."
          className="w-full h-32 p-4 border-2 border-gray-300 rounded-lg font-mono text-sm focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-200 resize-none"
        />
      </div>

      <div className="flex flex-col gap-3 sm:flex-row">
        <button
          onClick={handleAnalyze}
          disabled={isAnalyzing || (!inputText.trim() && !headerText.trim())}
          className="flex-1 bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
        >
          {isAnalyzing ? 'Analyzing...' : 'Check for Scam'}
        </button>

        <button
          onClick={handleClear}
          className="px-6 py-3 rounded-lg font-semibold border-2 border-gray-300 text-gray-700 hover:bg-gray-50 transition-colors"
        >
          Clear
        </button>
      </div>

      {result && (
        <div className={`p-6 rounded-lg border-2 ${getRiskColor(result.riskLevel)}`}>
          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between mb-4">
            <div>
              <h3 className="text-lg font-bold mb-2">Analysis Result</h3>
              <p className="text-sm leading-relaxed mb-4">{result.message}</p>
            </div>
            <div className="text-right">
              <div className="text-3xl font-bold mb-2">{result.riskScore}</div>
              <span className={`inline-block px-3 py-1 rounded-full text-xs font-bold ${getRiskBadgeColor(result.riskLevel)}`}>
                {result.riskLevel.toUpperCase()}
              </span>
            </div>
          </div>

          {result.headerSummary && (
            <div className="mb-4 p-4 rounded-lg bg-white/80 border border-gray-200">
              <h4 className="font-semibold mb-2">Header analysis</h4>
              <p className="text-sm text-gray-700 mb-2">{result.headerSummary}</p>
              {result.parsedHeaders && Object.keys(result.parsedHeaders).length > 0 && (
                <div className="grid gap-2 text-sm text-gray-700 sm:grid-cols-2">
                  {Object.entries(result.parsedHeaders).map(([key, value]) => (
                    <div key={key}>
                      <span className="font-semibold">{key.replace(/([A-Z])/g, ' $1')}: </span>
                      <span>{String(value)}</span>
                    </div>
                  ))}
                </div>
              )}
              {result.headerIssues?.length > 0 && (
                <ul className="text-sm text-gray-600 list-disc list-inside space-y-1 mt-3">
                  {result.headerIssues.map((issue, idx) => (
                    <li key={idx}>{issue}</li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {result.urlAnalysis && (
            <div className="mb-4 p-4 rounded-lg bg-white/80 border border-gray-200">
              <h4 className="font-semibold mb-2">URL reputation</h4>
              <p className="text-sm text-gray-700 mb-2">{result.urlAnalysis.summary}</p>
              <div className="space-y-2">
                {result.urlAnalysis.urls.map((item, idx) => (
                  <div key={idx} className="text-sm p-3 rounded border border-gray-200 bg-slate-50">
                    <div className="font-semibold">{item.url}</div>
                    <div className="text-xs text-gray-600">Status: {item.status}</div>
                    <div className="text-xs text-gray-600">{item.note}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.matches.length > 0 && (
            <div className="mt-6">
              <h4 className="font-semibold mb-3">Suspicious patterns found ({result.matches.length}):</h4>
              <ul className="space-y-2">
                {result.matches.map((match, idx) => (
                  <li key={idx} className="text-sm p-2 bg-white/50 rounded border-l-4 border-red-400">
                    <span className="font-mono font-semibold text-red-600">"{match.text}"</span>
                    <span className="text-gray-600 ml-2">— {match.keyword}</span>
                    <span className="ml-2 text-xs font-bold uppercase px-2 py-0.5 rounded" style={{
                      backgroundColor: match.risk === 'critical' ? '#fee2e2' : match.risk === 'high' ? '#fef3c7' : '#dbeafe',
                      color: match.risk === 'critical' ? '#991b1b' : match.risk === 'high' ? '#92400e' : '#1e40af',
                    }}>
                      {match.risk}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {result.riskScore === 0 && (
            <div className="mt-6 p-4 bg-white/50 rounded border-l-4 border-green-400">
              <p className="text-sm text-gray-700">
                <strong>Tips to stay safe:</strong>
              </p>
              <ul className="text-sm text-gray-600 mt-2 ml-4 list-disc space-y-1">
                <li>Never share passwords, PINs, or banking details</li>
                <li>Be wary of unsolicited offers or urgent requests</li>
                <li>Verify sender identity through official channels</li>
                <li>Check for spelling and grammar errors</li>
                <li>Hover over links before clicking (don't click suspicious links)</li>
              </ul>
            </div>
          )}
        </div>
      )}

      <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
        <h4 className="font-semibold text-blue-900 mb-3">How this detector works:</h4>
        <ul className="text-sm text-blue-800 space-y-1 ml-4 list-disc">
          <li>Analyzes text for scam patterns and suspicious keywords</li>
          <li>Checks headers for SPF, DKIM, and DMARC authentication issues</li>
          <li>Uses a backend proxy to look up URL reputation securely</li>
          <li>Shows clear warnings with suggested next steps</li>
        </ul>
      </div>
    </div>
  )
}
