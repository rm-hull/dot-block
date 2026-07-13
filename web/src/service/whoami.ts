interface User {
  user: string
  email: string
}

export async function fetchWhoAmI(): Promise<User> {
  const response = await fetch('/api/whoami')
  if (!response.ok) {
    throw new Error('Failed to fetch user info')
  }
  return response.json()
}