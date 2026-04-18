import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import AppLayout from "./AppLayout";
import Dashboard from "./pages/dashboard/Dashboard";
import Fim from "./pages/fim/Fim";
import Analysis from "./pages/analysis/Analysis";
import Chatbot from "./pages/chatbot/Chatbot";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 2 * 60 * 1000,
      retry: 1
    }
  }

})


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
        path: "/chatbot",
        element: <Chatbot/>
      },
      {
        path: "/analysis",
        element: <Analysis/>
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
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router}/>
    </QueryClientProvider>
  </StrictMode>,
)
