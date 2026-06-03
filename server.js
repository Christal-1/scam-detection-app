import path from 'path'
import express from 'express'
import dotenv from 'dotenv'

dotenv.config()

const app = express()
const port = process.env.PORT ? Number(process.env.PORT) : 4000
const apiKey = process.env.VIRUSTOTAL_API_KEY

app.use(express.json())

app.post('/api/url-reputation', async (req, res) => {
  const urls = Array.isArray(req.body?.urls) ? req.body.urls : []

  if (!urls.length) {
    return res.status(400).json({ message: 'Missing urls array in request body.' })
  }

  if (!apiKey) {
    return res.status(503).json({ message: 'VirusTotal API key is not configured on the server.' })
  }

  const reputation = []
  let totalRisk = 0

  for (const url of urls) {
    try {
      const form = new URLSearchParams({ url })
      const uploadResp = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: form.toString(),
      })

      if (!uploadResp.ok) {
        reputation.push({ url, status: 'error', note: `VirusTotal upload failed (${uploadResp.status})` })
        continue
      }

      const uploadData = await uploadResp.json()
      const analysisId = uploadData.data?.id
      if (!analysisId) {
        reputation.push({ url, status: 'error', note: 'VirusTotal did not return an analysis ID.' })
        continue
      }

      const analysisResp = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { 'x-apikey': apiKey },
      })
      if (!analysisResp.ok) {
        reputation.push({ url, status: 'error', note: `VirusTotal analysis failed (${analysisResp.status})` })
        continue
      }

      const analysisData = await analysisResp.json()
      const stats = analysisData.data?.attributes?.stats
      const malicious = stats?.malicious || 0
      const suspicious = stats?.suspicious || 0
      const verdict = malicious > 0 ? 'malicious' : suspicious > 0 ? 'suspicious' : 'clean'
      const risk = verdict === 'malicious' ? 20 : verdict === 'suspicious' ? 10 : 0
      totalRisk += risk
      reputation.push({
        url,
        status: verdict,
        malicious,
        suspicious,
        note: verdict === 'clean' ? 'No threats found.' : 'Potential risk detected.',
      })
    } catch (error) {
      reputation.push({ url, status: 'error', note: error.message })
    }
  }

  res.json({ urls: reputation, totalRisk, summary: reputation.length === 0 ? 'URL reputation could not be determined.' : 'URL reputation analysis completed.' })
})

const distPath = path.resolve('./dist')
app.use(express.static(distPath))

app.get('*', (req, res) => {
  res.sendFile(path.join(distPath, 'index.html'))
})

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`)
})
