// ============================================================================
// PASSWORD PROTECTION FOR /table-number/*
// ============================================================================
// This is a Netlify Edge Function. It runs BEFORE any page in the
// "table-number" folder is served, and blocks access until the correct
// password is entered.
//
// HOW TO SET THE PASSWORD (do this in the Netlify dashboard, not in code):
//   1. Go to your site in Netlify → Project configuration →
//      Environment variables.
//   2. Add a new variable:
//        Key:   TABLE_NUMBER_PASSWORD
//        Value: whatever password you want (e.g. a word only your guests know)
//   3. Redeploy the site for the variable to take effect.
//
// Keeping the password in an environment variable (instead of typed directly
// into this file) means it never shows up in your GitHub repo or in the
// public site code — anyone who views page source can't see it.
//
// HOW LOGIN PERSISTS: once someone enters the correct password, this sets
// a cookie in their browser that lasts 24 hours, so they won't be asked
// again until it expires or they clear cookies.
//
// TO CHANGE WHICH FOLDER THIS PROTECTS: edit the "path" line in the
// config export at the very bottom of this file.
// ============================================================================

const COOKIE_NAME = "table_number_auth";

export default async (request, context) => {
  const url = new URL(request.url);
  const password = Deno.env.get("TABLE_NUMBER_PASSWORD");

  // Safety check: if no password has been set in the Netlify dashboard yet,
  // show a clear message instead of silently locking everyone out (or worse,
  // silently letting everyone in).
  if (!password) {
    return new Response(
      renderPage({
        error: "No password has been configured yet. Set TABLE_NUMBER_PASSWORD in Netlify's Environment variables, then redeploy.",
      }),
      { status: 500, headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }

  // Check for a valid session cookie FIRST — before looking at the request
  // method at all, so that any future form added to this page (or a POST
  // from elsewhere) doesn't get mistaken for a password attempt once
  // someone's already logged in.
  const cookieHeader = request.headers.get("cookie") || "";
  const isAuthed = cookieHeader
    .split(";")
    .map((c) => c.trim())
    .includes(`${COOKIE_NAME}=granted`);

  if (isAuthed) {
    return context.next();
  }

  // Not logged in yet. Handle the password gate's own form submission.
  if (request.method === "POST") {
    const form = await request.formData();
    const submitted = (form.get("password") || "").toString();

    if (submitted === password) {
      const headers = new Headers();
      headers.set("Location", url.pathname);
      headers.append(
        "Set-Cookie",
        `${COOKIE_NAME}=granted; HttpOnly; Secure; SameSite=Strict; Max-Age=86400; Path=/table-number`
      );
      return new Response(null, { status: 303, headers });
    }

    // Wrong password — show the form again with an error
    return new Response(renderPage({ error: "That password didn't work. Please try again." }), {
      status: 401,
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  // Not logged in, and this is a normal page visit (GET) — show the gate.
  return new Response(renderPage({}), {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
};

// Renders a password prompt styled to match the rest of the wedding site
// (sage green background, pine text, same fonts). Edit colors/fonts here
// if you change them in styles.css — this page is served standalone, before
// the visitor is let through, so it can't load styles.css directly and
// repeats the key styles inline instead.
function renderPage({ error }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Table Number — Kennady &amp; Noah</title>
<style>
  @font-face{
    font-family: 'Exmouth';
    src: url('/fonts/exmouth_.woff2') format('woff2');
    font-weight: 400;
    font-style: normal;
    font-display: swap;
  }
  @font-face{
    font-family: 'Zanela';
    src: url('/fonts/Zanela-pglrR.woff2') format('woff2');
    font-weight: 400;
    font-style: normal;
    font-display: swap;
  }
  :root{
    --sage: #d2dfb0;
    --cream: #d2dfb0;
    --input-bg: #f6f4ea;
    --pine: #2d3a24;
    --pine-mid: #52623f;
    --pine-faint: rgba(45,58,36,0.18);
  }
  *{ margin:0; padding:0; box-sizing:border-box; }
  body{
    background: var(--sage);
    color: var(--pine);
    font-family: 'Zanela', Georgia, serif;
    min-height: 100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    padding: 28px;
  }
  .gate{
    background: var(--cream);
    border: none;
    padding: 48px 40px;
    max-width: 380px;
    width: 100%;
    text-align:center;
  }
  .gate h1{
    font-family: 'Exmouth', 'Brush Script MT', cursive;
    font-weight:400;
    font-size: 2.4rem;
    margin-bottom: 8px;
  }
  .gate p.sub{
    color: var(--pine-mid);
    font-size: 0.95rem;
    margin-bottom: 28px;
  }
  .gate input[type="password"]{
    width: 100%;
    padding: 12px 14px;
    font-family: 'Zanela', Georgia, serif;
    font-size: 1.05rem;
    border: 1px solid var(--pine-faint);
    background: var(--input-bg);
    color: var(--pine);
    margin-bottom: 16px;
  }
  .gate button{
    width: 100%;
    padding: 12px 14px;
    font-family: 'Zanela', Georgia, serif;
    font-size: 0.85rem;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    background: var(--pine);
    color: var(--sage);
    border: none;
    cursor: pointer;
  }
  .gate button:hover{ background: var(--pine-mid); }
  .error{
    color: #7a2e2e;
    font-size: 0.9rem;
    margin-bottom: 16px;
  }
</style>
</head>
<body>
  <div class="gate">
    <h1>Table Number</h1>
    <p class="sub">This page is password protected.</p>
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
    <form method="POST">
      <input type="password" name="password" placeholder="Enter password" autofocus required>
      <button type="submit">Enter</button>
    </form>
  </div>
</body>
</html>`;
}

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// This tells Netlify which URLs should be intercepted by this function.
// Change "/table-number/*" if you rename the folder.
export const config = {
  path: "/table-number/*",
};
