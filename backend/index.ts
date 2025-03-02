import dotenv from "dotenv"
dotenv.config()

import express from 'express';
import { removeAuthenticatedUser, authProvider, setupAuth } from './oauth';

const app = express()
if (authProvider) {
    setupAuth(app, authProvider)
} else {
    app.get("/logout", async (req, res) => {
        removeAuthenticatedUser(req, res)
        res.redirect("/")
    })
}

app.use("/", express.static("../frontend/dist"))
app.use("/", express.static("../frontend/public"))


app.listen(4000, () => {
	console.log(`Server is running on http://localhost:${4000}`);
});
