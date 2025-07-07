
import './App.css'
import { Register } from './pages/Authentication Page/Register'
import { Login } from './pages/Authentication Page/Login'
import { Home } from './pages/Simple Pages/Home'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import { MainDisplay } from './pages/Simple Pages/MainDisplay'
import { Errorpage } from './pages/Simple Pages/ErrorPage'
import { ProtectedRoute } from './pages/Simple Pages/ProtectedRoute'

 
const route = createBrowserRouter([
    {
      path: "/",
      element: <MainDisplay/>,
      errorElement: <Errorpage/>
    },

    {
      path: "/Home",
      element: (
        <ProtectedRoute>
          <Home/>
        </ProtectedRoute>
      ),
      errorElement: <Errorpage/>
    },

    {
      path: "/Register",
      element: <Register/>,
      errorElement: <Errorpage/>
    },

    {
      path: "/Login",
      element: <Login/>,
      errorElement: <Errorpage/>
    },

    


  ])

function App() {

  
 

  return <RouterProvider router={route}></RouterProvider>
}

export default App
