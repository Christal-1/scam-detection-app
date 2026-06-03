# Scam Detection App

A modern web application built with React and Tailwind CSS that helps users identify and protect themselves from scams. The app analyzes text messages, emails, and other content for common scam patterns and red flags.

## Features

- **Real-time Analysis**: Paste any suspicious message and get instant analysis
- **Risk Scoring**: Calculates a 0-100 risk score based on detected patterns
- **Pattern Detection**: Identifies common scam tactics including:
  - Financial/money scams
  - Urgency and pressure tactics
  - Brand impersonation
  - Phishing and malware attempts
  - Romance and advance-fee scams
- **Detailed Results**: Shows specific suspicious keywords and patterns found
- **Clean UI**: Modern, accessible interface built with React and Tailwind CSS
- **Optional Backend Proxy**: A lightweight backend proxy is included for secure VirusTotal URL reputation lookups

## Tech Stack

- **React 19** - UI framework
- **Vite** - Build tool
- **Tailwind CSS 4** - Styling
- **JavaScript** - Detection logic

## Getting Started

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

The app will be available at `http://localhost:5173`

## Optional VirusTotal URL Reputation

To enable URL reputation checks, copy `.env.example` to `.env` at the project root and add your key:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

Then run the app with the backend proxy so the API key is kept server-side.

```bash
npm run dev
```

The app will start both the frontend and backend, and the frontend will proxy `/api/url-reputation` to the backend server.

## How It Works

The scam detector uses rule-based pattern matching to identify suspicious elements:

1. **Pattern Matching**: Scans text for known scam phrases and keywords
2. **Risk Scoring**: Assigns risk points based on pattern severity
3. **Result Generation**: Provides actionable feedback and warnings

## Example Detections

The app detects patterns like:
- "Win money", "claim your reward"
- "Verify your account", "confirm password"
- "Bank details", "credit card information"
- "Urgent", "act now", "limited time"
- "Click here", "download now"
- And many more...

## Disclaimer

This tool uses rule-based pattern matching to detect common scam indicators. It may not catch all scams and should be used as a helper, not a replacement for critical thinking. When in doubt, contact the official organization directly.

## Future Enhancements

- Machine learning model for improved detection
- API integration for real-time threat data
- Browser extension for automatic email/SMS scanning
- Premium tier with advanced features
- Multi-language support

## Project History

Originally started as "TearCV", a resume builder with drag-and-drop functionality. Refactored to focus on cybersecurity and scam detection education.

## License

MIT
