/**
 * @fileoverview This Next.js API route handler serves as the main endpoint for the MCP (Multi-Capability Provider) adapter.
 * It handles incoming requests, performs OAuth 2.0 authentication to protect the endpoint,
 * and then delegates to the MCP handler to expose tools (like search and fetch) to authorized clients (e.g., ChatGPT plugins).
 * The dummy data and its access functions have been moved to `lib/data.ts` for better organization.
 */

import { createMcpHandler } from "@vercel/mcp-adapter";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import {
  oauth,
  Request as OAuthRequest,
  Response as OAuthResponse,
} from "@/lib/oauth-server";
import { searchArticles, fetchArticleById, Article } from "@/lib/data"; // Import data and functions

// Main handler function for GET, POST, DELETE requests to this API route.
const handler = async (req: NextRequest) => {
  if (process.env.NODE_ENV !== 'production') {
    console.log(`[MCP Transport Route] Received ${req.method} request to ${req.nextUrl.pathname}`);
  }

  // --- OAuth 2.0 Bearer Token Authentication --- 
  // All requests to this MCP endpoint must be authenticated using a Bearer token.
  // The token is validated using the OAuth2 server setup.
  const authorizationHeader = req.headers.get("Authorization");

  if (!authorizationHeader || !authorizationHeader.startsWith("Bearer ")) {
    return new NextResponse(
      JSON.stringify({
        error: "unauthorized",
        error_description: "Missing or invalid Bearer token",
      }),
      { status: 401, headers: { "Content-Type": "application/json" } }
    );
  }

  const oauthRequest = new OAuthRequest({
    headers: Object.fromEntries(req.headers.entries()),
    method: req.method.toUpperCase(),
    query: {},
    body: {},
  });
  // The `node-oauth2-server` library expects an OAuthResponse object to be passed in,
  // even if `authenticate()` doesn't primarily use it to *return* the main response body to the client here.
  // It might populate it with headers or other details in some scenarios or error cases.
  const oauthResponse = new OAuthResponse({}); 

  try {
    // Authenticate the request using the Bearer token.
    // `oauth.authenticate()` will verify the token, check its validity (e.g., expiration, scope).
    // Scopes can be specified if the endpoint requires specific permissions.
    // For this example, an empty scope array `[]` means any valid token is accepted.
    // If specific scopes like 'read_articles' or 'use_tools' were defined and granted,
    // they could be enforced here, e.g., { scope: ['read_articles'] }.
    const authenticatedToken = await oauth.authenticate(
      oauthRequest,
      oauthResponse,
      { scope: [] } // Adjust scopes as needed for more granular access control.
    ); // Pass empty scope array or specific scopes if needed
    if (!authenticatedToken || !authenticatedToken.user) {
      console.error(
        "[MCP Handler] Authentication failed or token did not contain user information."
      );
      return new NextResponse(
        JSON.stringify({
          error: "unauthorized",
          error_description: "Invalid token or user not found.",
        }),
        { status: 401, headers: { "Content-Type": "application/json" } }
      );
    }

    if (process.env.NODE_ENV !== 'production') {
      // Log only non-sensitive user identifier or a generic success message.
      const userId = authenticatedToken.user?.id || 'unknown_user_id'; // Adjust if user object structure is different or id is not present
      console.log(`[MCP Handler] User authenticated successfully. User ID: ${userId}`);
    }
    // At this point, the user (or client application) is authenticated.
    // The `authenticatedToken` object contains information about the token, client, and user.
    // This information can be used for logging, auditing, or passing to the MCP tools if needed.

    // --- Proceed to MCP Handler --- 
    // If authentication is successful, the request is passed to the `createMcpHandler`.
  } catch (error: any) {
    console.error("[MCP Handler] Authentication error:", error);
    const status = error.code || error.status || 401; // Default to 401 for auth errors
    const message = error.message || "Authentication failed.";
    return new NextResponse(
      JSON.stringify({ error: "unauthorized", error_description: message }),
      { status, headers: { "Content-Type": "application/json" } }
    );
  }

  // Initialize the MCP handler from `@vercel/mcp-adapter`.
  // This function takes a setup callback to define tools, capabilities, and other configurations.
  return createMcpHandler(
    async (server) => {
      // --- Tool Definitions --- 
      // Define the tools that this MCP will expose. Each tool has a name, description,
      // input schema (using Zod), and an async handler function.

      // Example Tool 1: 'search'
      // Searches the dummy article dataset based on a query string.
      server.tool(
        "search",
        "Search articles. Pass in a query string.",
        {
          query: z.string().describe("The search query for articles."),
        },
        async ({ query }) => {
          if (process.env.NODE_ENV !== 'production') {
            console.log(
              `[MCP Tool Search - API Route] Searching articles for: "${query}"...`
            );
          }
          const searchResults = await searchArticles(query, 10);
          if (process.env.NODE_ENV !== 'production') {
            console.log(
              `[MCP Tool Search - API Route] Found ${searchResults.results.length} articles.`
            );
          }
          return {
            structuredContent: { results: searchResults.results },
            content: [
              {
                type: "text",
                text: JSON.stringify(searchResults),
              },
            ],
          };
        }
      );

      // Example Tool 2: 'fetch'
      // Fetches a specific article from the dummy dataset by its ID.
      server.tool(
        "fetch",
        "Fetch an article by its ID.",
        {
          id: z.string().describe("The ID of the article to fetch."),
        },
        async ({ id }) => {
          if (process.env.NODE_ENV !== 'production') {
            console.log(
              `[MCP Tool Fetch - API Route] Fetching article with ID: ${id}...`
            );
          }
          const article = await fetchArticleById(id);
          if (!article) {
            if (process.env.NODE_ENV !== 'production') {
              console.log(
                `[MCP Tool Fetch - API Route] Article with ID ${id} not found.`
              );
            }
            return {
              content: [
                {
                  type: "text",
                  text: `Article with ID "${id}" not found.`,
                },
              ],
              structuredContent: {
                error: `Article with ID ${id} not found`,
              },
            };
          }
          if (process.env.NODE_ENV !== 'production' && article) {
            console.log(
              `[MCP Tool Fetch - API Route] Fetched article: ${article.title}`
            );
          }
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(article),
              },
            ],
            structuredContent: article as unknown as { [x: string]: unknown },
          };
        }
      );
    },
    // --- MCP Configuration --- 
    // Second argument to `createMcpHandler` is the configuration object.
    {
      // `capabilities` describes the tools available to the MCP client.
      capabilities: {
        tools: {
          search: {
            description: "Search for articles.",
          },
          fetch: {
            description: "Fetch an article by ID.",
          },
        },
      },
    },
    // Third argument to `createMcpHandler` provides additional options for the adapter.
    {
      basePath: "/api", // The base path for the API routes, used for constructing URLs.
      verboseLogs: process.env.NODE_ENV !== 'production', // Enable verbose logs in development.
      maxDuration: 60, // Maximum execution time for a tool request in seconds.
      // `redisUrl` is optional; if provided, it can be used for caching or other Redis-backed features by the adapter.
      redisUrl: process.env.REDIS_URL, 
    }
  )(req);
};

export { handler as GET, handler as POST, handler as DELETE };
