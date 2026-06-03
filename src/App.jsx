import React from 'react'
import ScamAnalyzer from './components/ScamAnalyzer'

function App() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50">
      {/* Decorative blobs */}
      <div className="fixed top-0 left-0 w-96 h-96 rounded-full z-0 opacity-30 mix-blend-multiply filter blur-3xl pointer-events-none" style={{ backgroundColor: 'rgba(59, 130, 246, 0.3)' }} />
      <div className="fixed bottom-0 right-0 w-96 h-96 rounded-full z-0 opacity-30 mix-blend-multiply filter blur-3xl pointer-events-none" style={{ backgroundColor: 'rgba(168, 85, 247, 0.3)' }} />

      {/* Main content */}
      <div className="relative z-10 min-h-screen flex flex-col">
        <header className="pt-12 pb-8 px-6">
          <div className="max-w-2xl mx-auto text-center">
            <h1 className="text-5xl font-bold text-gray-900 mb-3">
              🛡️ Scam Detection App
            </h1>
            <p className="text-lg text-gray-600">
              Analyze messages, emails, and texts to detect potential scams. Our AI-powered scanner identifies suspicious patterns and alerts you to red flags.
            </p>
          </div>
        </header>

        <main className="flex-1 px-6 pb-12">
          <div className="max-w-2xl mx-auto">
            <div className="bg-white rounded-lg shadow-lg p-8">
              <ScamAnalyzer />
            </div>
          </div>
        </main>

        <footer className="py-8 px-6 border-t border-gray-200">
          <div className="max-w-2xl mx-auto text-center text-sm text-gray-600">
            <p>
              💡 <strong>Disclaimer:</strong> This tool uses rule-based pattern matching to detect common scam indicators. It may not catch all scams and should be used as a helper, not a replacement for critical thinking. When in doubt, contact the official organization directly.
            </p>
          </div>
        </footer>
      </div>
    </div>
  )
}

export default App
