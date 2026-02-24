import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import { LoginPage } from './components/LoginPage'
import { DashboardPage } from './components/DashboardPage'
import { ProtectedRoute } from './components/ProtectedRoute'

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/patient" element={<LoginPage />} />
        <Route
          path="/patient/dashboard"
          element={
            <ProtectedRoute>
              <DashboardPage />
            </ProtectedRoute>
          }
        />
        <Route path="*" element={<Navigate to="/patient" replace />} />
      </Routes>
    </AuthProvider>
  )
}
