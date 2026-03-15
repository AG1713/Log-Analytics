import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import AppLayout from "./AppLayout";
import Dashboard from "./pages/dashboard/Dashboard";
import Fim from "./pages/fim/Fim";
import Alerts from "./pages/alerts/Alerts";
import Chatbot from "./pages/chatbot/Chatbot";


const router = createBrowserRouter([
  {
    path:"/",
    element:<AppLayout/>,
    children:[
      {
        index: true,
        element: <Dashboard/>
      },
      {
        path: "/alerts",
        element: <Alerts/>
      },
      {
        path: "/chatbot",
        element: <Chatbot/>
      },
      {
        path: "/fim",
        element: <Fim/>
      },
    ]
  }
])

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <RouterProvider router={router}/>
  </StrictMode>,
)
