import { Request, Response } from "express"
import * as t from "io-ts"
import JWT from "jsonwebtoken"
import { getEnv } from "./env"
import { Left, isLeft, left } from "fp-ts/lib/Either"
import { PathReporter } from "io-ts/lib/PathReporter"
import { ISOTimeStamp } from '../common/domain'

export function optional<T extends t.Type<any>>(c: T) {
    return t.union([c, t.undefined, t.null])
}

// User info from keycloak
export type OAuthAuthenticatedUser = {
    name: string
    email: string
    picture?: string
	groups: string[]
}

// Info about login
export type LoginInfo = OAuthAuthenticatedUser & {
    timestamp: ISOTimeStamp | undefined
}

export interface AuthProvider {
    getAuthPageURL: () => Promise<string>
    getAccountFromCode: (code: string) => Promise<OAuthAuthenticatedUser>
    logout?: (req: Request, res: Response) => Promise<void>
}

export function decodeOrThrow<T>(codec: t.Type<T, any>, input: any): T {
    const validationResult = codec.decode(input)
    if (isLeft(validationResult)) {
        throw new ValidationError(validationResult)
    }
    return validationResult.right
}

class ValidationError extends Error {
    constructor(errors: Left<t.Errors>) {
        super(report_(errors.left))
    }
}

function report_(errors: t.Errors) {
    return PathReporter.report(left(errors)).join("\n")
}

type GenericOAuthConfig = {
    OIDC_CONFIG_URL: string
    OIDC_CLIENT_ID: string
    OIDC_CLIENT_SECRET: string
    OIDC_LOGOUT?: string
}

export const genericOIDCConfig: GenericOAuthConfig | null = {
          OIDC_CONFIG_URL: getEnv("OIDC_CONFIG_URL"),
          OIDC_CLIENT_ID: getEnv("OIDC_CLIENT_ID"),
          OIDC_CLIENT_SECRET: getEnv("OIDC_CLIENT_SECRET"),
          OIDC_LOGOUT: process.env.OIDC_LOGOUT,
      }

export function GenericOIDCAuthProvider(config: GenericOAuthConfig): AuthProvider {
    console.log(`Setting up generic OAuth authentication using client id ${config.OIDC_CLIENT_ID}`)

    const callbackUrl = 'http://localhost:4000/callback' //TODO: change to get url from env

    const openIdConfiguration = (async () => {
        const response = await fetch(config.OIDC_CONFIG_URL)
        return decodeOrThrow(OpenIdConfiguration, await response.json())
    })()

	// Get account info
    async function getAccountFromCode(code: string): Promise<OAuthAuthenticatedUser> {
        const response = await fetch((await openIdConfiguration).token_endpoint, {
            method: "POST",
            headers: {
                "content-type": "application/x-www-form-urlencoded",
            },
            body: `grant_type=authorization_code&code=${encodeURIComponent(code)}&client_id=${encodeURIComponent(
                config.OIDC_CLIENT_ID,
            )}&client_secret=${config.OIDC_CLIENT_SECRET}&redirect_uri=${callbackUrl}`,
        })

        const body = await response.json()

        const idToken = JWT.decode(body.id_token)
        const user = decodeOrThrow(IdToken, idToken)
        return {
            email: user.email,
            name: "name" in user ? user.name : user.preferred_username,
            picture: user.picture ?? undefined,
			groups: user.groups
        }
    }

	// Get Keycloak login page
    async function getAuthPageURL() {
        const scopes = "email openid profile"
        const state = "TODO"
        const redirectUri = callbackUrl
        return `${(await openIdConfiguration).authorization_endpoint}?scope=${encodeURIComponent(
            scopes,
        )}&response_type=code&state=${encodeURIComponent(state)}&redirect_uri=${encodeURIComponent(
            redirectUri,
        )}&client_id=${config.OIDC_CLIENT_ID}`
    }

    const shouldHandleLogout = config.OIDC_LOGOUT

	// Get Keycloak logout page
    async function getLogoutUrl(): Promise<string> {
        if (config.OIDC_LOGOUT && config.OIDC_LOGOUT !== "true") {
            return config.OIDC_LOGOUT
        }

        const logoutUrl = (await openIdConfiguration).end_session_endpoint

        if (!logoutUrl) {
            throw Error(
                `OIDC configuration at ${config.OIDC_CONFIG_URL} does not specify end_session_endpoint. Use OIDC_LOGOUT environment variable to define the logout endpoint explicitly.`,
            )
        }

        return logoutUrl
    }

    const logout = shouldHandleLogout
        ? async (req: Request, res: Response) => {
              res.redirect(await getLogoutUrl())
          }
        : undefined

    return {
        getAccountFromCode,
        getAuthPageURL,
        logout,
    }
}



const OpenIdConfiguration = t.type({
    authorization_endpoint: t.string,
    token_endpoint: t.string,
    end_session_endpoint: optional(t.string),
})

const IdToken = t.union([
    t.type({
        email: t.string,
        name: t.string,
        picture: optional(t.string),
        groups: t.array(t.string)
    }),
    t.type({
        email: t.string,
        preferred_username: t.string,
        picture: optional(t.string),
        groups: t.array(t.string)
    }),
])

