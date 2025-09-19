"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { BACKEND_HOST, BACKEND_PORT } from "@/app/model";
import Link from "next/link";

export default function Main() {
    const router = useRouter();
    const [loading, setLoading] = useState(false);

    async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
        e.preventDefault();
        setLoading(true);

        const form = new FormData(e.currentTarget);
        fetch(`http://${BACKEND_HOST}:${BACKEND_PORT}/api/user/register`, {
            method: "POST",
            body: form,
        }).then(resp => {
            if (resp.ok) {
                router.push("/");
                alert("Registration successful.");
                return;
            } else {
                resp.json().then(data => {
                    alert(data.message);
                })
            }
        }).catch(error => {
            console.error(error);
            alert("Unknown error.");
        }).finally(() => {
            setLoading(false);
        })
    }

    return (
        <>
            <h1><Link href={"/"}>Akashic</Link></h1>
            <h3>User register</h3>
            <div className={"container"}>
                <form method={"POST"} onSubmit={handleSubmit} id="register-form">
                    <label>
                        <span>email</span>
                        <input name={"email"} type={"email"} required autoComplete={"email"} />
                    </label>
                    <label>
                        <span>password</span>
                        <input name={"password"} type={"password"} required />
                    </label>
                    <button type="submit">{loading ? "Loading" : "Register"}</button>
                </form>
            </div>
        </>
    );
}
