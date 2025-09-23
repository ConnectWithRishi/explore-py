"use client";

import { useState } from "react";
import { useMsal } from "@azure/msal-react";
import { loginRequest } from "@/lib/auth-config";
import { Button } from "@workspace/ui/components/button";

export function LoginButton() {
  const { instance, accounts, inProgress } = useMsal();
  const [isLoading, setIsLoading] = useState(false);

  const handleLogin = async () => {
    setIsLoading(true);
    try {
      await instance.loginPopup(loginRequest);
    } catch (error) {
      console.error("Login failed:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = async () => {
    setIsLoading(true);
    try {
      await instance.logoutPopup({
        postLogoutRedirectUri: "http://localhost:3000",
      });
    } catch (error) {
      console.error("Logout failed:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const isAuthenticated = accounts.length > 0;

  if (inProgress === "login" || isLoading) {
    return <Button disabled>Loading...</Button>;
  }

  return (
    <div className="flex items-center gap-4">
      {isAuthenticated ? (
        <>
          <span className="text-sm text-muted-foreground">
            Welcome, {accounts[0]?.name || accounts[0]?.username || "User"}
          </span>
          <Button onClick={handleLogout} variant="outline">
            Logout
          </Button>
        </>
      ) : (
        <Button onClick={handleLogin}>Login with Azure</Button>
      )}
    </div>
  );
}
