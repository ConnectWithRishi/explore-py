"use client";

import { useState, useEffect } from "react";
import { useMsal } from "@azure/msal-react";
import { Button } from "@workspace/ui/components/button";
import { LoginButton } from "@/components/login-button";
import {
  FastApiClient,
  getAccessTokenForApi,
  UserInfo,
  HealthResponse,
} from "@/lib/api-client";

export default function Page() {
  const { instance, accounts, inProgress } = useMsal();
  const [healthData, setHealthData] = useState<HealthResponse | null>(null);
  const [userData, setUserData] = useState<UserInfo | null>(null);
  const [protectedData, setProtectedData] = useState<string>("");
  const [oboData, setOboData] = useState<string>("");
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string>("");

  // Debug state for auth data
  const [debugAuth, setDebugAuth] = useState<Record<string, unknown> | null>(
    null
  );
  const [showDebug, setShowDebug] = useState(false);

  const isAuthenticated = accounts.length > 0;

  // Debug: Log authentication data when user logs in/out
  useEffect(() => {
    if (isAuthenticated && accounts[0]) {
      const authData = {
        account: {
          localAccountId: accounts[0].localAccountId,
          name: accounts[0].name,
          username: accounts[0].username,
          tenantId: accounts[0].tenantId,
          environment: accounts[0].environment,
          homeAccountId: accounts[0].homeAccountId,
        },
        instance: {
          clientId: instance.getConfiguration().auth.clientId,
          authority: instance.getConfiguration().auth.authority,
        },
        inProgress,
        timestamp: new Date().toISOString(),
      };

      setDebugAuth(authData);
      console.log("🔐 AUTH DEBUG - User logged in:", authData);
    } else {
      setDebugAuth(null);
      console.log("🔐 AUTH DEBUG - User logged out");
    }
  }, [accounts, instance, inProgress, isAuthenticated]);

  const handleApiCall = async (
    operation: string,
    apiCall: () => Promise<unknown>
  ) => {
    setError("");
    setLoading(operation);

    try {
      console.log(`🚀 Starting ${operation} API call`);
      const result = await apiCall();
      console.log(`✅ ${operation} API call successful:`, result);

      const resultStr =
        typeof result === "string" ? result : JSON.stringify(result, null, 2);

      switch (operation) {
        case "health":
          setHealthData(result as HealthResponse);
          break;
        case "me":
          setUserData(result as UserInfo);
          break;
        case "protected":
          setProtectedData(resultStr);
          break;
        case "obo":
          setOboData(resultStr);
          break;
      }
    } catch (err) {
      const error = err as {
        response?: { data?: { detail?: string }; status?: number };
        message: string;
      };

      console.error(`❌ ${operation} API call failed:`, error);

      setError(
        `${operation} failed: ${error.response?.data?.detail || error.message}`
      );
    } finally {
      setLoading(null);
    }
  };

  const testHealthEndpoint = () => {
    const client = new FastApiClient();
    handleApiCall("health", () => client.getHealth());
  };

  const testProtectedEndpoint = async () => {
    if (!isAuthenticated) {
      setError("Please login first");
      return;
    }

    try {
      const accessToken = await getAccessTokenForApi(instance, accounts[0]!);
      const client = new FastApiClient(accessToken);
      handleApiCall("protected", () => client.getProtected());
    } catch (err) {
      const error = err as { message: string };
      console.error("❌ Token acquisition failed:", error);
      setError(`Token acquisition failed: ${error.message}`);
    }
  };

  const testMeEndpoint = async () => {
    if (!isAuthenticated) {
      setError("Please login first");
      return;
    }

    try {
      const accessToken = await getAccessTokenForApi(instance, accounts[0]!);
      const client = new FastApiClient(accessToken);
      handleApiCall("me", () => client.getMe());
    } catch (err) {
      const error = err as { message: string };
      console.error("❌ Token acquisition failed:", error);
      setError(`Token acquisition failed: ${error.message}`);
    }
  };

  const testOboEndpoint = async () => {
    if (!isAuthenticated) {
      setError("Please login first");
      return;
    }

    try {
      const accessToken = await getAccessTokenForApi(instance, accounts[0]!);
      const client = new FastApiClient(accessToken);
      handleApiCall("obo", () => client.getOboGraphMe());
    } catch (err) {
      const error = err as { message: string };
      console.error("❌ Token acquisition failed:", error);
      setError(`Token acquisition failed: ${error.message}`);
    }
  };

  return (
    <div className="container mx-auto p-8 max-w-6xl">
      <div className="flex flex-col gap-8">
        <header className="text-center">
          <h1 className="text-3xl font-bold mb-4">
            FastAPI Azure Entra Auth Test
          </h1>
          <p className="text-muted-foreground mb-6">
            Test authentication patterns with your FastAPI backend
          </p>
          <LoginButton />
        </header>

        {error && (
          <div className="bg-red-50 border border-red-200 rounded-md p-4">
            <p className="text-red-800">{error}</p>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Public Endpoints */}
          <div className="border rounded-lg p-6">
            <h2 className="text-xl font-semibold mb-4">Public Endpoints</h2>
            <div className="space-y-4">
              <Button
                onClick={testHealthEndpoint}
                disabled={loading === "health"}
                className="w-full"
              >
                {loading === "health" ? "Loading..." : "Test Health Endpoint"}
              </Button>

              {healthData && (
                <div className="bg-green-50 border border-green-200 rounded p-3">
                  <pre className="text-sm">
                    {JSON.stringify(healthData, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>

          {/* Pattern A - Direct Token Validation */}
          <div className="border rounded-lg p-6">
            <h2 className="text-xl font-semibold mb-4">
              Pattern A - Token Validation
            </h2>
            <div className="space-y-4">
              <Button
                onClick={testProtectedEndpoint}
                disabled={!isAuthenticated || loading === "protected"}
                className="w-full"
              >
                {loading === "protected"
                  ? "Loading..."
                  : "Test Protected Endpoint"}
              </Button>

              <Button
                onClick={testMeEndpoint}
                disabled={!isAuthenticated || loading === "me"}
                className="w-full"
              >
                {loading === "me" ? "Loading..." : "Test /me Endpoint"}
              </Button>

              {protectedData && (
                <div className="bg-blue-50 border border-blue-200 rounded p-3">
                  <pre className="text-sm">{protectedData}</pre>
                </div>
              )}

              {userData && (
                <div className="bg-blue-50 border border-blue-200 rounded p-3">
                  <pre className="text-sm">
                    {JSON.stringify(userData, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>

          {/* Pattern B - OBO Flow */}
          <div className="border rounded-lg p-6 md:col-span-2">
            <h2 className="text-xl font-semibold mb-4">
              Pattern B - On-Behalf-Of Flow
            </h2>
            <div className="space-y-4">
              <Button
                onClick={testOboEndpoint}
                disabled={!isAuthenticated || loading === "obo"}
                className="w-full"
              >
                {loading === "obo" ? "Loading..." : "Test OBO Graph Endpoint"}
              </Button>

              {oboData && (
                <div className="bg-purple-50 border border-purple-200 rounded p-3">
                  <pre className="text-sm">{oboData}</pre>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Authentication Status */}
        <div className="border rounded-lg p-6">
          <h2 className="text-xl font-semibold mb-4">Authentication Status</h2>
          {isAuthenticated ? (
            <div className="space-y-2">
              <p className="text-green-600">✅ Authenticated</p>
              <p>
                <strong>User:</strong>{" "}
                {accounts[0]?.name || accounts[0]?.username}
              </p>
              <p>
                <strong>Account ID:</strong> {accounts[0]?.localAccountId}
              </p>
              <p>
                <strong>Tenant:</strong> {accounts[0]?.tenantId}
              </p>
            </div>
          ) : (
            <p className="text-orange-600">
              ❌ Not authenticated - please login to test protected endpoints
            </p>
          )}
        </div>

        {/* Debug Section */}
        <div className="border rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-semibold">Debug Information</h2>
            <Button
              onClick={() => setShowDebug(!showDebug)}
              variant="outline"
              size="sm"
            >
              {showDebug ? "Hide" : "Show"} Debug
            </Button>
          </div>

          {showDebug && (
            <div className="space-y-6">
              {/* Auth Debug */}
              <div>
                <h3 className="text-lg font-medium mb-3 text-blue-700">
                  🔐 Authentication Data
                </h3>
                {debugAuth ? (
                  <div className="bg-blue-50 border border-blue-200 rounded p-3">
                    <pre className="text-sm overflow-auto max-h-64">
                      {JSON.stringify(debugAuth, null, 2)}
                    </pre>
                  </div>
                ) : (
                  <p className="text-gray-500 italic">
                    No authentication data available
                  </p>
                )}
              </div>

              {/* Console Log Instructions */}
              <div className="bg-yellow-50 border border-yellow-200 rounded p-4">
                <h4 className="font-medium text-yellow-800 mb-2">
                  💡 Console Logging
                </h4>
                <div className="space-y-2 text-sm text-yellow-700">
                  <p>
                    <strong>
                      Open your browser&apos;s Developer Tools (F12)
                    </strong>{" "}
                    and check the Console tab to see detailed logging:
                  </p>
                  <ul className="list-disc list-inside space-y-1 ml-4">
                    <li>
                      <strong>🔐 AUTH DEBUG</strong> - Authentication events and
                      user data
                    </li>
                    <li>
                      <strong>🔑</strong> - Token acquisition details and
                      previews
                    </li>
                    <li>
                      <strong>🌐 API REQUEST/RESPONSE</strong> - All API calls
                      with headers and data
                    </li>
                    <li>
                      <strong>🚀 ✅ ❌</strong> - API call status and results
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
