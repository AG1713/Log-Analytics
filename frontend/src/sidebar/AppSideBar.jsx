import { Sidebar, SidebarContent, SidebarGroup, SidebarGroupContent, SidebarHeader, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarTrigger } from '@/components/ui/sidebar'
import { LayoutDashboard, ShieldAlert, Bot, FolderSearch } from 'lucide-react'
import { Link, useLocation } from 'react-router-dom'

const sidebarItems = [
  { label: "Dashboard",  icon: LayoutDashboard, path: "/" },
  { label: "Alerts",     icon: ShieldAlert,     path: "/alerts" },
  { label: "Chatbot",    icon: Bot,             path: "/chatbot" },
  { label: "FIM",        icon: FolderSearch,    path: "/fim" },
]

const AppSideBar = () => {
  const location = useLocation()

  return (
    <Sidebar collapsible='icon'>
      <SidebarHeader className="flex flex-row items-center justify-between p-3">
        <span className="font-semibold text-sm group-data-[collapsible=icon]:hidden whitespace-nowrap">
          Log Analytics
        </span>
        <SidebarTrigger />
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              {sidebarItems.map(item => (
                <SidebarMenuItem key={item.path}>
                  <SidebarMenuButton
                    asChild
                    isActive={location.pathname === item.path}
                  >
                    <Link to={item.path}>
                      <item.icon size={16} />
                      <span>{item.label}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
    </Sidebar>
  )
}

export default AppSideBar