
import { useEffect, useState } from 'react'
import { supabase } from './lib/supabase'

function App() {
  const [status, setStatus] = useState('Checking connection...')

  useEffect(() => {
    async function checkConnection() {
      try {
        const { error } = await supabase.auth.getSession()

        if (error) {
          setStatus(`Connection error: ${error.message}`)
          return
        }

        setStatus('Supabase client initialized successfully!')
      } catch (err) {
        setStatus(
          `Error: ${err instanceof Error ? err.message : String(err)}`
        )
      }
    }

    void checkConnection()
  }, [])

  return (
    <main style={{ padding: '2rem', fontFamily: 'sans-serif' }}>
      <h1>Smart Carpool</h1>
      <p>{status}</p>
    </main>
  )
}

export default App
