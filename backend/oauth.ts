import Cookies from "cookies"
import { Express, Request, Response } from "express"
import { GenericOIDCAuthProvider, genericOIDCConfig, OAuthAuthenticatedUser, LoginInfo, AuthProvider } from "./generic-oidc-auth"
import JWT from "jsonwebtoken"
import { IncomingMessage, ServerResponse } from "http"
import { newISOTimeStamp } from '../common/domain';

const secret = "asdfgh"



export function setAuthenticatedUser(req: IncomingMessage, res: ServerResponse, userInfo: OAuthAuthenticatedUser) {
    const loginInfo: LoginInfo = { ...userInfo, timestamp: newISOTimeStamp() }
    const jwt = JWT.sign(loginInfo, secret)
    new Cookies(req, res).set("user", jwt, {
        maxAge: 365 * 24 * 3600 * 1000,
        httpOnly: false,
    }) // Max 365 days expiration
}

export function removeAuthenticatedUser(req: IncomingMessage, res: ServerResponse) {
    new Cookies(req, res).set("user", "", { maxAge: 0, httpOnly: true })
}

export function setupAuth(app: Express, provider: AuthProvider) {
    app.get("/login", async (req, res) => {
        new Cookies(req, res).set("returnTo", parseReturnPath(req), {
            maxAge: 24 * 3600 * 1000,
            httpOnly: true,
        }) // Max 24 hours
        const authUrl = await provider.getAuthPageURL()
        res.setHeader("content-type", "text/html")
        res.send(`Signing in...<script>document.location='${authUrl}'</script>`)
    })

    app.get("/logout", async (req, res) => {
        removeAuthenticatedUser(req, res)
        if (provider.logout) {
            await provider.logout(req, res)
        } else {
            res.redirect(parseReturnPath(req))
        }
    })

    app.get("/callback", async (req, res) => {
        const code = (req.query?.code as string) || ""
        const cookies = new Cookies(req, res)
        const returnTo = cookies.get("returnTo") || "/"
        cookies.set("returnTo", "", { maxAge: 0, httpOnly: true })
        console.log("Verifying auth", code)
        try {
            const userInfo = await provider.getAccountFromCode(code)
            console.log("Found", userInfo)
            setAuthenticatedUser(req, res, userInfo)
            res.redirect(returnTo)
        } catch (e) {
            console.error(e)
            res.status(500).send("Internal error")
        }
    })

    function parseReturnPath(req: Request) {
        return (req.query.returnTo as string) || "/"
    }
}

export const authProvider: AuthProvider | null = genericOIDCConfig
    ? GenericOIDCAuthProvider(genericOIDCConfig)
    : null
