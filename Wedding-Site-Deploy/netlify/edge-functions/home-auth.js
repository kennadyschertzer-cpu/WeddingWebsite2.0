// ============================================================================
// PASSWORD PROTECTION FOR THE SITE — EXCEPT THE RSVP PAGE
// ============================================================================
// This is a Netlify Edge Function. It runs BEFORE any page on the site is
// served (every page EXCEPT rsvp.html — see "excludedPath" in the config
// export at the bottom), and blocks access until the correct password
// is entered.
//
// Note: table-number/ has its OWN separate password on top of this one
// (see table-number-auth.js). So a visitor needs this site-wide password
// first, and then the Table Number password on top of that to reach that
// specific page. That's intentional layered protection, not a bug.
//
// HOW TO SET THE PASSWORD (do this in the Netlify dashboard, not in code):
//   1. Go to your site in Netlify → Project configuration →
//      Environment variables.
//   2. Add a new variable:
//        Key:   HOME_PASSWORD
//        Value: (the password you want guests to use)
//      Mark it "Contains secret values", same value for all deploy
//      contexts (same steps you already used for TABLE_NUMBER_PASSWORD).
//   3. Trigger a redeploy for the variable to take effect.
//
// HOW LOGIN PERSISTS: once someone enters the correct password, this sets
// a cookie in their browser that lasts 24 hours, so they won't be asked
// again until it expires or they clear cookies.
//
// TO EXCLUDE MORE PAGES LATER: add more paths to the "excludedPath" array
// in the config export at the very bottom of this file.
// ============================================================================

const COOKIE_NAME = "home_auth";

export default async (request, context) => {
  const url = new URL(request.url);
  const password = Deno.env.get("HOME_PASSWORD");

  // Safety check: if no password has been set in the Netlify dashboard yet,
  // show a clear message instead of silently locking everyone out (or worse,
  // silently letting everyone in).
  if (!password) {
    return new Response(
      renderPage({
        error: "No password has been configured yet. Set HOME_PASSWORD in Netlify's Environment variables, then redeploy.",
      }),
      { status: 500, headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }

  // Check for a valid session cookie FIRST — before looking at the request
  // method at all. This matters because forms on the site also submit via
  // POST. If we checked "is this a POST?" before checking the cookie, an
  // already-logged-in visitor's form submission would get mistaken for a
  // password attempt and blocked.
  const cookieHeader = request.headers.get("cookie") || "";
  const isAuthed = cookieHeader
    .split(";")
    .map((c) => c.trim())
    .includes(`${COOKIE_NAME}=granted`);

  if (isAuthed) {
    // Already logged in — let EVERYTHING through untouched.
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
        `${COOKIE_NAME}=granted; HttpOnly; Secure; SameSite=Strict; Max-Age=86400; Path=/`
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

// Renders a password prompt styled to match the rest of the wedding site,
// using your actual Exmouth/Zanela font files (loaded from /fonts, same as
// the real site) since this page is served before the visitor is let through
// and can't rely on styles.css alone without repeating the @font-face rules.
function renderPage({ error }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Kennady &amp; Noah</title>
<link rel="preload" href="/fonts/exmouth_.woff2" as="font" type="font/woff2" crossorigin fetchpriority="high">
<link rel="preload" href="/fonts/Zanela-pglrR.woff2" as="font" type="font/woff2" crossorigin fetchpriority="high">
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
    font-family: 'Zanela', serif;
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
    max-width: 420px;
    width: 100%;
    text-align:center;
  }
  .gate-image{
    max-width: 260px;
    width: 100%;
    margin: 0 auto 28px;
  }
  .gate-image img{
    width: 100%;
    height: auto;
    display: block;
    object-fit: contain;
  }
  .eyebrow{
    display:block;
    font-size: 0.75rem;
    letter-spacing: 0.32em;
    text-transform: uppercase;
    color: var(--pine-mid);
    font-weight: 400;
    margin-bottom: 28px;
  }
  .gate p.sub{
    color: var(--pine-mid);
    font-size: 0.95rem;
    margin-bottom: 28px;
  }
  .gate input[type="password"]{
    width: 100%;
    padding: 12px 14px;
    font-family: 'Zanela', serif;
    font-size: 1.05rem;
    border: 1px solid var(--pine-faint);
    background: var(--input-bg);
    color: var(--pine);
    margin-bottom: 16px;
  }
  .gate button{
    width: 100%;
    padding: 12px 14px;
    font-family: 'Zanela', serif;
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
    <div class="gate-image">
      <img src="/images/venue-sketch.jpeg" alt="Old Monroe Distilling Co. venue sketch">
    </div>
    <span class="eyebrow">Please Enter Our Password</span>
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
// "/*" means every page and asset on the site, EXCEPT whatever is listed
// in excludedPath — currently just rsvp.html, so that page loads with no
// password prompt at all while everything else stays protected.
export const config = {
  path: "/*",
  excludedPath: "/rsvp.html",
};
