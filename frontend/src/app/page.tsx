"use client";

import Link from "next/link";
import { BACKEND_HOST, BACKEND_PORT } from "@/app/model";
import { useEffect, useState } from "react";

export default function Main() {
  const [loggedIn, setLoggedIn] = useState(false);
  const [username, setUsername] = useState<string|null>(null);
  const [loading, setLoading] = useState(false);

  const backend_base = `http://${BACKEND_HOST}:${BACKEND_PORT}`;
  const redirect_uri = `http://localhost:3000/api/auth/callback`;
  const params = new URLSearchParams({
    response_type: "code",
    client_id: "parent",
    redirect_uri: redirect_uri,
  });
  const login_url = `${backend_base}/auth/authorize?${params.toString()}`;

  useEffect(() => {
    let mounted = true;
    async function check() {
      console.log("Checking login status...");
      setLoading(true);
      try {
        console.log(document.cookie);
        const token = document.cookie.split(";").find((c) => c.trim().startsWith("access_token"))?.split("=")[1] ?? "";
        console.log(token);
        if (!token) return;
        const res = await fetch(`${backend_base}/auth/whoami`, {
          method: "GET",
          headers: {
            accept: "application/json",
            "Authorization": `Bearer ${token}`,
          },
        });
        if (!mounted) return;
        if (res.ok) {
          const data = await res.json();
          console.log(data);
          if (data.authorized) {
            setLoggedIn(true);
            setUsername(data.email);
          } else {
            setLoggedIn(false);
            setUsername(null);
          }
        } else {
          setLoggedIn(false);
          setUsername(null);
        }
      } catch (error) {
        console.error(error);
        setLoggedIn(false);
        setUsername(null);
      } finally {
        if (mounted) setLoading(false);
      }
    }
    check();
    return () => {
      mounted = false;
    }
  }, []);

  async function logout() {
    try {
      const res = await fetch("/api/auth/logout", {
        method: "POST",
      });
      if (res.ok) {
        setLoggedIn(false);
        setUsername(null);
      } else {
        console.error("Failed to logout");
      }
    } catch (error) {
      console.error(error);
    }
  }

  return (
    <>
      <h1><Link href={"/"}>Akashic</Link></h1>
      <div className={"container-col"}>
        {loading ? (
          <div>Loading...</div>
        ) : loggedIn ? (
          <>
            <div>Welcome{username ? `, ${username}` : ""}</div>
            <button onClick={logout}>Logout</button>
          </>
        ) : (
          <>
            <a href={"/register"}>register</a>
            <a href={login_url}>login</a>
          </>
        )}
      </div>
    </>
  );
}
