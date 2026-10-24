import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.jsx';
import '@icon-park/react/styles/index.css';
import './styles.css';
import './ui-cleanup.css';

createRoot(document.getElementById('root')).render(<App />);
