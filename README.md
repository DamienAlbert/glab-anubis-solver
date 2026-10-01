# glab-anubis-solver

Lets [`glab`](https://gitlab.com/gitlab-org/cli) talk to a GitLab instance protected by
[Anubis](https://github.com/TecharoHQ/anubis).

Anubis serves a proof-of-work challenge before letting HTTP requests through. Browsers
solve it in JavaScript and get a signed cookie; CLI tools get the challenge HTML page
instead of API responses. `anubis-cookie` solves the challenge the same way a browser
does, caches the cookie, and glab sends it with every request through its
`custom_headers` setting.

It pays the proof-of-work Anubis asks for, nothing more: one solve per cookie lifetime,
no parallel solving, a fixed and truthful User-Agent. If your GitLab admins declined an
Anubis exemption for the API, let them know you use this.

## Requirements

- Python 3.8+ (standard library only)
- glab with `custom_headers` / `valueFromCommand` support (1.120 works)

## Install

1. Put this directory on your `PATH` (or symlink/copy the files into a directory that is).
   - `anubis-cookie`: Linux, macOS, Git Bash
   - `anubis-cookie.cmd`: Windows. glab is a Windows program, so it uses this one even
     when launched from Git Bash.
2. Copy `config.example.ini` to `config.ini` and set your host:

   ```ini
   [anubis-cookie]
   host = gitlab.example.com
   user_agent = glab-cli anubis-cookie/1.0
   ```

   The config file is looked up in this order: `$ANUBIS_COOKIE_CONFIG`, `config.ini` next
   to the script, `~/.config/anubis-cookie/config.ini`.
3. Add the headers to your host in glab's config (`~/.config/glab-cli/config.yml`, or
   `%LOCALAPPDATA%\glab-cli\config.yml` on Windows):

   ```yaml
   hosts:
       gitlab.example.com:
           # ...
           custom_headers:
               - name: Cookie
                 valueFromCommand: anubis-cookie gitlab.example.com
               - name: User-Agent
                 valueFromCommand: anubis-cookie --user-agent
   ```

   The custom `User-Agent` replaces glab's default one.
4. Check it: `glab api version --hostname gitlab.example.com` should print JSON.
   `GLAB_DEBUG_HTTP=1` shows the headers glab sends.

## Usage

```
anubis-cookie [<host>]               print "<cookie-name>=<jwt>" (cached)
anubis-cookie --refresh [<host>]     ignore the cache and solve again
anubis-cookie --user-agent           print the configured User-Agent
```

`<host>` defaults to `host` from the config file. Only the header value goes to stdout,
logs go to stderr, and the exit code is non-zero on failure, as glab expects.

glab runs the commands once per process. You don't need to call `anubis-cookie`
yourself, except with `--refresh` if glab gets the challenge page again (see below).

## How it works

1. `GET https://<host>/` and read the challenge JSON from
   `<script id="anubis_challenge">`.
2. Depending on `rules.algorithm`:
   - `fast` / `slow`: find the smallest `nonce` such that
     `sha256(randomData + nonce)` starts with `difficulty` hex zeros;
   - `metarefresh`: wait the delay of the `<meta http-equiv="refresh">` tag and follow it;
   - anything else (e.g. `preact`): fail with an error.
3. Submit to `/.within.website/x/cmd/anubis/api/pass-challenge` (with `id`, `response`,
   `nonce`, `redir`, `elapsedTime`) without following the redirect, and keep the
   `*-auth` cookie it sets. The challenge cookies from step 1 are sent back.
4. Cache `{cookie_name, value, exp, user_agent}` in `~/.cache/anubis-cookie/<host>.json`
   (mode 600). `exp` comes from the JWT payload; the cookie is solved again when it
   expires in less than an hour or when the User-Agent changes.

A lock file makes concurrent glab processes wait for a single solve.

## Troubleshooting

- **glab prints the "Making sure you're not a bot!" page**: the challenge records the
  client IP, so a cookie obtained on another network (VPN on/off) may be refused. Run
  `anubis-cookie --refresh <host>`.
- **`no Anubis challenge`**: the host didn't serve a challenge, e.g. your IP is exempt.
  glab needs a non-empty header value, so remove the `custom_headers` in that case.
- **`unsupported Anubis algorithm`**: the instance uses a challenge this script doesn't
  implement.

## License

Copyright (C) 2026 Damien Albert

This program is free software; you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation; either
version 2 of the License, or (at your option) any later version. See [LICENSE](LICENSE).
