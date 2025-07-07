import signupImage from "../../assets/images/sign-image.png";
import { NavLink } from "react-router-dom";
import { useState, ChangeEvent, FormEvent } from "react";
import { useNavigate } from "react-router-dom";

export function Register() {
  const navigate = useNavigate();

  const [formError, setFormError] = useState<string>("");
  const [signupFormData, setSignupFormData] = useState({
    username: "",
    email: "",
    name: "",
    password: "",
    confirmpassword: "",
  });

  function handleChange(event: ChangeEvent<HTMLInputElement>) {
    const { name, value } = event.target;
    setSignupFormData((prevData) => ({
      ...prevData,
      [name]: value,
    }));

    console.log(signupFormData);
  }

  async function handleFormSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const { email, password, confirmpassword } = signupFormData;
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailPattern.test(email)) {
      setFormError("Please enter a valid email address.");
      return;
    }

    if (password !== confirmpassword) {
      setFormError("Passwords do not match.");
      return;
    }

    setFormError("");

    try {
      const response = await fetch("http://localhost:5000/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(signupFormData),
      });

      const data = await response.json();

      console.log(data);
      if (data.token) {
        console.log("User registered successfully:", data);
        setSignupFormData({
          username: "",
          email: "",
          name: "",
          password: "",
          confirmpassword: "",
        });
        localStorage.setItem("token", data.token);
        navigate("/Home");
      } else {
        setFormError(data.message || "Registration failed.");
      }
    } catch (error) {
      console.error("Error during registration:", error);
      setFormError("Something went wrong. Please try again.");
    }

    console.log("Submitted Data:", signupFormData);
  }

  return (
    <>
      <div className="main-signup flex justify-center items-center w-full h-screen bg-[#85193C]">
        <div className="signup flex justify-center bg-white w-max h-max rounded-2xl">
          <div className="signup-image bg-green-200 w-[50%] h-[440px] overflow-hidden rounded-tl-2xl rounded-bl-2xl">
            <img className="w-full h-full object-cover" src={signupImage} alt="Signup" />
          </div>

          <div className="signup-content px-[20px] w-[50%]">
            <div className="signup-heading py-[20px]">
              <h1 className="text-center text-[30px] font-semibold">Sign Up</h1>
            </div>

            <form onSubmit={handleFormSubmit} className="flex flex-col gap-3.5">
              <input onChange={handleChange} value={signupFormData.username} className="bg-white outline-0 py-[5px] border-b-2 border-[#FFD63A] px-[10px]" type="text" name="username" placeholder="Username" />
              <input onChange={handleChange} value={signupFormData.email} className="bg-white outline-0 py-[5px] border-b-2 border-[#FFD63A] px-[10px]" type="email" name="email" placeholder="Email" />
              <input onChange={handleChange} value={signupFormData.name} className="bg-white outline-0 py-[5px] border-b-2 border-[#FFD63A] px-[10px]" type="text" name="name" placeholder="Name" />
              <input onChange={handleChange} value={signupFormData.password} className="bg-white outline-0 py-[5px] border-b-2 border-[#FFD63A] px-[10px]" type="password" name="password" placeholder="Password" />
              <input onChange={handleChange} value={signupFormData.confirmpassword} className="bg-white outline-0 py-[5px] border-b-2 border-[#FFD63A] px-[10px]" type="password" name="confirmpassword" placeholder="Confirm Password" />

              <div className="signup-button flex justify-center mt-[20px]">
                <button className="bg-transparent text-[#FFD63A] border-2 border-[#FFD63A] w-max py-[5px] px-[10px] rounded-3xl cursor-pointer"> Register </button>
              </div>

              {formError && (
                <p className="text-red-600 text-center font-light">{formError}</p>
              )}
            </form>

            <div className="goto-login mt-[5px]">
              <p className="text-center"> Already have an account?{" "}
                <NavLink to="/Login" className="text-[#FFD63A] cursor-pointer"> Login </NavLink>
              </p>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
