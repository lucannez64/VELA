import React from 'react'
import ReactDOM from 'react-dom/client'
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow'
import App from './App'
import QuickSearchWindow from './views/QuickSearchWindow'
import './index.css'

// The `quick-search` window is a standalone popup with its own minimal UI;
// every other window label gets the full app.
const isQuickSearch = getCurrentWebviewWindow().label === 'quick-search'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    {isQuickSearch ? <QuickSearchWindow /> : <App />}
  </React.StrictMode>,
)
