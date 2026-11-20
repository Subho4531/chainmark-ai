import { usePath } from './routerState'
import Landing from './Landing'
import Testbench from './Testbench'
import DashboardLayout from './dashboard/DashboardLayout'

const DASHBOARD_PATHS = ['/dashboard', '/playground', '/api-keys', '/docs']

export default function App() {
  const path = usePath()

  if (path === '/testbench') {
    return <Testbench />
  }

  if (DASHBOARD_PATHS.includes(path) || path.startsWith('/dashboard/')) {
    return <DashboardLayout />
  }

  return <Landing />
}
