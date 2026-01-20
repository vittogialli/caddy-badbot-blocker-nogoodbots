# Caddy Bad Bot Blocker

This is a module for the Caddy v2 web server that acts as an HTTP request matcher. Its purpose is to identify and block malicious bots, aggressive crawlers, and spam referrers, based on the excellent blocklists provided by the [mitchellkrogza/nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker) project.

The module checks the IP address, User-Agent, and Referer of each incoming request and compares them against the blocklists.

## Features

-   Blocks requests based on the client's IP address.
-   Blocks requests based on the User-Agent.
-   Blocks requests based on the Referer.
-   Uses blocklists from the `nginx-ultimate-bad-bot-blocker` project by default.
-   Allows excluding specific IP addresses or User-Agents from being blocked.
-   Allows customizing the URLs from which to download the lists.
-   Provides structured and customizable logging for blocked requests.
-   Easy to setup with fail2ban

## Installation

To use this module, you need to build a custom version of Caddy that includes it. This process is made simple by the `xcaddy` tool.

1.  Ensure you have [Go installed](https://golang.org/doc/install) (version 1.25 or later).
2.  Install `xcaddy`:
    ```bash
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
    ```
3.  Build Caddy with the `caddy-badbot-blocker` module:
    ```bash
    xcaddy build --with github.com/vittogialli/caddy-badbot-blocker-nogoodbots
    ```
4.  This command will create a `caddy` executable in the current directory. Replace your existing Caddy binary with this new file, or use it directly to run the server.

## Configuration

Configuration is done directly in your `Caddyfile`. Here is a complete and commented example showing how to use the module.

```caddy
# Example Caddyfile

(blocker) {
	route {
		@banned badbotblocker {
			refresh_interval 24h
		}
		route @banned {
			abort
		}
	}
}

localhost {
	route {
		import blocker

		respond "Hello, world!"
	}

}
```

### Configuration Explained

1.  **`@banned` Matcher**: A named matcher `@banned` is defined. Our `badbotblocker` module analyzes the request. If it matches an entry in the blocklists, the matcher returns `true`.
2.  **`route @banned`**: This block defines what to do with a request that matches `@banned`.
    -   `log_skip`: This directive tells Caddy to not write this request to the standard access log, keeping it clean.
    -   `abort`: This immediately terminates the connection, blocking the bot.
3.  **Logging**:
    -   The `log badbotblocker` block in the global options creates a separate log file (`bad_bots.log`) that will contain **only** the detailed information (in JSON format) about the requests we have blocked.
    -   The standard `log` block within the site configures the `access.log`. Blocked requests won't appear here because of the `log_skip` directive used previously.

## Credits

This module would not be possible without the fantastic work of the blocklists provided and maintained by the **[mitchellkrogza/nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker)** project.
