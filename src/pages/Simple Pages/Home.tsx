import { useNavigate } from "react-router-dom";
import { useState, useEffect, ChangeEvent } from "react";

interface UpdateForm {
    name: string;
    username: string;
    email: string;
}

export function Home() {

    const navigate = useNavigate();
    const token = localStorage.getItem("token");
    const API = "http://localhost:5000/api/auth";

    const [showConfirmPopup, setShowConfirmPopup] = useState<boolean>(false);
    const [showUpdatePopup, setShowUpdatePopup] = useState<boolean>(false);
    const [showError, setShowError] = useState<boolean>(false);
    const [formError, setFormError] = useState<string>("");
    const [userName, setUserName] = useState<string>("Guest");
    const [updateForm, setUpdateForm] = useState<UpdateForm>({
        name: "",
        username: "",
        email: ""
    });

    useEffect(() => {
        fetch(`${API}/me`, {
            method: "GET",
            headers: {
                Authorization: `Bearer ${token}`,
            },
        })
            .then((res) => res.json())
            .then((data) => {
                if (data.user) {
                    setUserName(data.user.name);
                    setUpdateForm({
                        name: data.user.name,
                        username: data.user.username,
                        email: data.user.email
                    });
                }
            })
            .catch((err) => {
                console.error("Error fetching user data:", err);
            });
    }, []);

    function handleLogout() {
        localStorage.removeItem("token");
        navigate("/login");
    }

    function handleDeleteClick() {
        setShowConfirmPopup(true);
    }

    function handleCancelDelete() {
        setShowConfirmPopup(false);
    }

    function handleConfirmDelete() {

        fetch(`${API}/delete`, {
            method: "DELETE",
            headers: {
                Authorization: `Bearer ${token}`,
            },
        })
            .then((res) => res.json())
            .then((data) => {
                alert(data.message);
                localStorage.removeItem("token");
                setShowConfirmPopup(false);
                navigate("/register");
            })
            .catch((err) => {
                console.error("Error deleting account:", err);
                setShowConfirmPopup(false);
            });
    }

    function handleUpdateClick() {
        setShowUpdatePopup(true);
    }

    function handleUpdateChange(event: ChangeEvent<HTMLInputElement>) {
        const { name, value } = event.target;
        setUpdateForm(prev => ({
            ...prev,
            [name]: value
        }));
    }

    function handleUpdateSubmit() {
        const { name, username } = updateForm;

        if (name && username) {

            setShowError(false);

            fetch(`${API}/update`, {
                method: "PUT",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(updateForm)
            })
                .then(res => res.json())
                .then(data => {
                    alert(data.message);
                    setUserName(data.user.name);
                    setShowUpdatePopup(false);
                })
                .catch(err => {
                    console.error("Update failed:", err);
                });

        } else {
            setShowError(true);
            setFormError("All fields are required");
        }

    }

    return (
        <>
            {showConfirmPopup && (
                <div className="fixed inset-0 flex items-center justify-center bg-[#00000078] z-50">
                    <div className="bg-white p-6 rounded-xl shadow-xl w-[90%] max-w-sm text-center">
                        <h2 className="text-xl font-semibold mb-4 text-[#85193C]">Delete Account</h2>
                        <p className="text-gray-700 mb-6">Are you sure you want to delete your account? This action cannot be undone.</p>
                        <div className="flex justify-center gap-4">
                            <button onClick={handleConfirmDelete} className="bg-[#85193C] text-white py-2 px-4 rounded-full cursor-pointer">Yes, Delete</button>
                            <button onClick={handleCancelDelete} className="bg-gray-300 text-[#85193C] py-2 px-4 rounded-full cursor-pointer">Cancel</button>
                        </div>
                    </div>
                </div>
            )}

            {showUpdatePopup && (
                <div className="fixed inset-0 flex items-center justify-center bg-[#00000078] z-50">
                    <div className="bg-white p-6 rounded-xl shadow-xl w-[90%] max-w-sm">
                        <h2 className="text-xl font-semibold text-[#85193C] mb-4">Update Profile</h2>
                        <div className="flex flex-col gap-3">
                            <input onChange={handleUpdateChange} value={updateForm.name} name="name" placeholder="Name" className="border border-gray-300 px-3 py-2 rounded-md" />
                            <input onChange={handleUpdateChange} value={updateForm.username} name="username" placeholder="Username" className="border border-gray-300 px-3 py-2 rounded-md" />
                        </div>
                        {showError && <p className="text-red-500 text-sm mt-2">{formError}</p>}
                        <div className="flex justify-end gap-3 mt-4">
                            <button onClick={handleUpdateSubmit} className="bg-[#85193C] text-white px-4 py-2 rounded-full cursor-pointer">Save</button>
                            <button onClick={() => setShowUpdatePopup(false)} className="bg-gray-300 text-[#85193C] px-4 py-2 rounded-full cursor-pointer">Cancel</button>
                        </div>
                    </div>
                </div>
            )}

            <div className="homescreen bg-[#85193C] w-full h-screen flex flex-col">
                <div className="navbar bg-white flex justify-between items-center px-8 py-4 rounded-b-2xl shadow-md">
                    <div className="displayName text-xl font-semibold text-[#85193C]">
                        <p>Welcome, {userName}</p>
                    </div>

                    <div className="functions flex gap-4">
                        <button onClick={handleLogout} className="bg-transparent text-[#85193C] border-2 border-[#FFD63A] py-2 px-4 rounded-full cursor-pointer"> Logout </button>
                        <button onClick={handleUpdateClick} className="bg-transparent text-[#85193C] border-2 border-[#FFD63A] py-2 px-4 rounded-full cursor-pointer"> Update </button>
                        <button onClick={handleDeleteClick} className="bg-transparent text-[#85193C] border-2 border-[#FFD63A] py-2 px-4 rounded-full cursor-pointer"> Delete Account </button>
                    </div>
                </div>

                <div className="flex-1 flex items-center justify-center text-white text-2xl font-medium">
                    <p>This is your home screen content</p>
                </div>
            </div>
        </>
    )
}
