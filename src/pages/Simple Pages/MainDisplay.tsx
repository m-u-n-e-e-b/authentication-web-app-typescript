import { NavLink } from "react-router-dom"
export function MainDisplay(){

    return(
        <>
        <div className="homescreen bg-[#85193C] w-full h-screen flex flex-col items-center justify-center px-4">

            <h1 className="text-white text-4xl font-semibold mb-8">Main Display</h1>

            <div className="flex flex-col sm:flex-row gap-6">
                <NavLink to="/Register" className="bg-transparent text-white border-2 border-[#FFD63A] py-3 px-6 rounded-full hover:bg-[#FFD63A] hover:text-[#85193C] transition text-lg text-center" > Go to Signup </NavLink>
                <NavLink to="/Login" className="bg-transparent text-white border-2 border-[#FFD63A] py-3 px-6 rounded-full hover:bg-[#FFD63A] hover:text-[#85193C] transition text-lg text-center" > Go to Login </NavLink>
            </div>
        </div>
        </>

    )
}