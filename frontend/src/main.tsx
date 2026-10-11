import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import '@fontsource-variable/inter'
import '@fontsource-variable/jetbrains-mono'

import { App } from './App'
import { createQueryClient } from './api/queryClient'
import { JobsProvider } from './app/JobsProvider'
import { ThemeProvider } from './theme/ThemeProvider'
import { ToastProvider } from './ui/ToastProvider'
import './index.css'

const container = document.getElementById('root')
if (container === null) {
  throw new Error('index.html is missing the #root element; the bundle cannot mount')
}

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={createQueryClient()}>
      <ThemeProvider>
        <ToastProvider>
          <BrowserRouter>
            <JobsProvider>
              <App />
            </JobsProvider>
          </BrowserRouter>
        </ToastProvider>
      </ThemeProvider>
    </QueryClientProvider>
  </StrictMode>,
)
