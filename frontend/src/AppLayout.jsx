import React from 'react'
import { SidebarProvider, SidebarTrigger } from './components/ui/sidebar'
import AppSideBar from './sidebar/AppSideBar'
import { Outlet } from 'react-router-dom'

// Commands for running the frontend
// cd frontend (if terminal is not already in the frontend folder)
// npm install
// npm run dev

// NOTE: even if the venv from backend is active in this terminal in vscode, the above commands won't nterfere with it
// in short, u are safe to run the above commands even if venv is activated.


const AppLayout = () => {
  return (
    <SidebarProvider>
        <AppSideBar/>
        <main className="h-screen w-screen flex flex-1">
          <SidebarTrigger />
          <Outlet />
        </main>

    </SidebarProvider>
  )
}

export default AppLayout
