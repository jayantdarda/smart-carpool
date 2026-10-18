
import { useEffect, useState } from 'react'
import { StyleSheet, Text, View } from 'react-native'
import { supabase } from './lib/supabase'

export default function App() {
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
    <View style={styles.container}>
      <Text style={styles.heading}>Smart Carpool</Text>
      <Text style={styles.status}>{status}</Text>
    </View>
  )
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 24,
  },
  heading: {
    fontSize: 28,
    fontWeight: 'bold',
    marginBottom: 12,
  },
  status: {
    fontSize: 16,
    textAlign: 'center',
  },
})
