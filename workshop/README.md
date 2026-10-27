# Workshop 9 companion lab

This classroom-only application accompanies Workshop_9_Beginner_Guide.tex.
It preserves the workshop's sessions, JWTs, and route-based authorisation topics.
The guide explains how to assemble the code incrementally. This folder contains
its completed version for checking your work.

## Run locally

1. Open a terminal in this folder.
2. Run `npm install` (or `npm ci` to use the supplied lockfile exactly).
3. Copy `.env.example` to a new file called `.env` using your editor.
4. Run this command twice, copying each output into a different secret setting:
   `node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"`
5. Keep `NODE_ENV=development` and `PORT=3000` for this local exercise.
6. Run `npm start` or `node server.mjs`.
7. Open http://localhost:3000/login for sessions or
   http://localhost:3000/loginjwt for JWTs.

Demo accounts (not real accounts):
- brad / Student123! (student)
- alex / Admin123! (admin)

The fixture stores plain-text demo passwords. Do not deploy it or replace the
course project's real UserService with it. The server binds to the local machine.
Sessions use memory and a 60-second cookie. Demo tokens expire in two minutes;
JWT login tokens expire in three minutes. Calling /create-token overwrites the
JWT login cookie with a demonstration token, so keep those exercises separate.

The original module-auth repository could not be retrieved during preparation.
These example files are a separate lab, not verified edits to that repository.
Follow the guide's integration section with the instructor-provided checkout.
