"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { BACKEND_HOST, BACKEND_PORT } from "@/app/model";
import Link from "next/link";

// export default function Main() {
//     const [loading, setLoading] = useState(false);
//     return (
//         <>
//             <h1><Link href={"/"}>Akashic</Link></h1>
//             <h3>User login</h3>
//             <div className={"container"}>
//                 <form method={"POST"} action={`http://${BACKEND_HOST}:${BACKEND_PORT}/api/user/login`} id="login-form">
//                     <label>
//                         <span>email</span>
//                         <input name={"email"} type={"email"} required autoComplete={"email"} />
//                     </label>
//                     <label>
//                         <span>password</span>
//                         <input name={"password"} type={"password"} required />
//                     </label>
//                     <button type="submit">{loading ? "Loading" : "Login"}</button>
//                 </form>
//             </div>
//         </>
//     );
// }

export default function Main() {
    const [loading, setLoading] = useState(false);
    const router = useRouter();

    async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
        e.preventDefault();
        setLoading(true);

        const form = new FormData(e.currentTarget);
        fetch(`http://${BACKEND_HOST}:${BACKEND_PORT}/api/user/login`, {
            method: "POST",
            body: form,
            credentials: "include",
            headers: {
                accept: "application/json",
            }
        }).then(resp => {
            return resp.json();
        }).then(data => {
            if (data.redirect_uri) {
                router.push(data.redirect_uri);
                alert("Login successful.");
                return;
            } else if (data.message) {
                alert(data.message);
                return;
            }
        }).catch(err => {
            alert("Failed to login. Please try again later.");
            console.error(err);
            return;
        }).finally(() => {
            setLoading(false);
        });
    }

    return (
        <>
            <h1><Link href={"/"}>Akashic</Link></h1>
            <h3>User login</h3>
            <div className={"container"}>
                <form method={"POST"} onSubmit={handleSubmit} id="login-form">
                    <label>
                        <span>email</span>
                        <input name={"email"} type={"email"} required autoComplete={"email"} />
                    </label>
                    <label>
                        <span>password</span>
                        <input name={"password"} type={"password"} required />
                    </label>
                    <button type="submit">{loading ? "Loading" : "Login"}</button>
                </form>
            </div>
        </>
    );
}
