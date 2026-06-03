import fs from 'fs'
import { analyzeText, highlightSuspiciousWords } from '../src/utils/scamDetector.js'

const email = `Dear Christal Haines

Dear Candidate,

Your application eligible for RELIANCE Interview
We are pleased to invite you to the next stage of the interview process.

More Details Here

 
Dear Christal Haines

Your application eligible for TCS Interview
We are pleased to invite you to the next stage of the interview process.

Date & Venue Here
If you wish to opt out of all type of emails, click Unsubscribe.`

const result = analyzeText(email)
console.log(JSON.stringify(result, null, 2))

// Also print highlighted snippet if matches exist
if (result.matches && result.matches.length) {
  const highlighted = highlightSuspiciousWords(email, result.matches)
  fs.writeFileSync('./detector_highlighted.html', `<html><body><pre>${highlighted}</pre></body></html>`)
  console.log('\nHighlighted output written to detector_highlighted.html')
}
