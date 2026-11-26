import { useEffect } from 'react'
import { usePath, navigate } from './routerState'
import { AuthProvider, useAuth } from './auth/AuthContext'
import AuthPage from './auth/AuthPage'
import Landing from './Landing'
import Testbench from './Testbench'
import DashboardLayout from './dashboard/DashboardLayout'

const DASHBOARD_PATHS = ['/dashboard', '/playground', '/api-keys', '/docs']

function AppRouter() {
  const path = usePath()
  const { user, loading } = useAuth()
  const isProtected = DASHBOARD_PATHS.includes(path) || path.startsWith('/dashboard/')
  const isAuthRoute = path === '/login' || path === '/signup'

  useEffect(() => {
    if (!loading && user && isAuthRoute) {
      navigate('/dashboard')
    }
  }, [loading, user, isAuthRoute])

  if (path === '/testbench') {
    return <Testbench />
  }

  if (isAuthRoute) {
    if (loading) {
      return <div className="auth-loading">Checking workspace session…</div>
    }
    return <AuthPage mode={path === '/signup' ? 'signup' : 'login'} redirectTo="/dashboard" />
  }

  if (isProtected) {
    if (loading) {
      return <div className="auth-loading">Verifying session…</div>
    }
    if (!user) {
      return <AuthPage mode="login" redirectTo={path} />
    }
    return <DashboardLayout />
  }

  return <Landing />
}

export default function App() {
  return (
    <AuthProvider>
      <AppRouter />
    </AuthProvider>
  )
}
