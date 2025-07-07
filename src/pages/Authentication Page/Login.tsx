import { NavLink, useNavigate } from "react-router-dom";
import signupImage from "../../assets/images/sign-image.png";
import { useState, ChangeEvent, FormEvent } from "react";

export function Login() {

    const navigate = useNavigate();
    const [formError, setFormError] = useState<string>("");

    const [loginFormData, setLoginFormData] = useState<{
        email: string;
        password: string;
    }>({
        email: "",
        password: "",
    });

    async function handleFormSubmit(event: FormEvent<HTMLFormElement>) {
        event.preventDefault();

        try {
            const response = await fetch("http://localhost:5000/api/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(loginFormData),
            });

            const data = await response.json();

            if (data.token) {
                console.log("Login successful:", data);
                localStorage.setItem("token", data.token);

                setLoginFormData({
                    email: "",
                    password: "",
                });

                navigate("/Home");
            } 
            else {
                setFormError(data.message || "Login failed.");
            }
        } 

        catch (error: unknown) {
            console.error("Login error:", error);
            setFormError("An error occurred while logging in.");
        }
    }

    function handleChange(event: ChangeEvent<HTMLInputElement>) {
        const { name, value } = event.target;
        setLoginFormData((prevData) => ({
            ...prevData,
            [name]: value,
        }));
        console.log(loginFormData);
    }

    return (
        <>
            <div className="main-signup flex justify-center items-center w-full h-screen bg-[#85193C]">

                <div className="signup flex justify-center bg-white w-max h-max rounded-2xl ">

                    <div className="signup-content flex flex-col justify-center px-[30px] w-[50%]">

                        <div className="signup-heading py-[20px]">
                            <h1 className="text-center text-[30px] font-semibold ">Login</h1>
                        </div>

                        <form onSubmit={handleFormSubmit} className="flex flex-col gap-3.5">
                            <input onChange={handleChange} value={loginFormData.email} className="bg-white outline-0 py-[5px] border-b-2 border-[#FFD63A] pr-[10px] pl-[10px]" type="email" name="email" placeholder="Email" />
                            <input onChange={handleChange} value={loginFormData.password} className="bg-white outline-0 py-[5px] border-b-2 border-[#FFD63A] pr-[10px] pl-[10px]" type="password" name="password" placeholder="Password" />
                            
                            <div className="signup-button flex justify-center mt-[20px]">
                                <button className="bg-transparent text-[#FFD63A] border-2 border-[#FFD63A] w-max py-[5px] px-[20px] rounded-3xl cursor-pointer">Login</button>
                            </div>

                            {formError && (
                                <p className="text-red-600 text-center font-light">{formError}</p>
                            )}
                        </form>

                        <div className="goto-login mt-[20px]">
                            <p className="text-center">Create an Account <NavLink to="/Register" className="text-[#FFD63A] cursor-pointer">Register</NavLink></p>
                        </div>
                    </div>

                    <div className="singup-image bg-green-200 w-[50%] h-[440px] overflow-hidden rounded-br-2xl rounded-tr-2xl">
                        <img className="w-full h-full object-fill" src={signupImage} alt="Signup" />
                    </div>
                </div>
            </div>
        </>
    );
}
