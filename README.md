# Safer Fetch MCP Server

<!-- mcp-name: io.github.modelcontextprotocol/server-fetch -->

A Model Context Protocol server that provides web content fetching capabilities **with built-in prompt injection safeguards**. This server enables LLMs to retrieve and process content from web pages, converting HTML to markdown for easier consumption, while protecting against malicious content that could manipulate the LLM.

## ⚠️ Disclaimer

**This software is provided "as is" without warranty of any kind.** While this server implements prompt injection detection and mitigation measures, **no security solution is 100% effective**. The safeguards implemented are designed to reduce risk but cannot guarantee complete protection against all prompt injection attacks. 

Users should:
- Exercise caution when fetching content from untrusted sources
- Review fetched content before acting on it in sensitive contexts
- Understand that determined attackers may find ways to bypass detection
- Not rely solely on these safeguards for security-critical applications

The maintainers are not responsible for any damages or security incidents resulting from the use of this software.

## Security Features

This server includes prompt injection safeguards to protect LLMs from malicious web content:

### 1. Content Boundary Wrapping
All fetched content is wrapped in security boundary tags with a **random boundary ID** (to prevent escape attacks). The wrapper includes:
- Clear instructions that content should be treated as **DATA ONLY**, not as instructions
- Critical security rules for the LLM to follow
- Source URL attribution

### 2. Prompt Injection Pattern Detection
Content is scanned for 20+ suspicious patterns including:
- **Instruction overrides**: "ignore previous instructions", "disregard prior prompts"
- **Role manipulation**: "you are now", "act as", "pretend to be"  
- **System prompt attacks**: "new system prompt", "override instructions"
- **Jailbreak attempts**: "developer mode", "DAN mode", "bypass restrictions"
- **Output manipulation**: "do not mention", "keep this secret"
- **Encoded instructions**: Base64 patterns, "decode and execute"

When suspicious patterns are detected:
- A `SECURITY_WARNING` is added to the output
- The LLM is instructed to spawn a subagent for independent review
- If confirmed malicious, the LLM should HALT and inform the user

> [!CAUTION]
> This server can access local/internal IP addresses and may represent a security risk. Exercise caution when using this MCP server to ensure this does not expose any sensitive data.

The fetch tool will truncate the response, but by using the `start_index` argument, you can specify where to start the content extraction. This lets models read a webpage in chunks, until they find the information they need.

### Available Tools

- `fetch` - Fetches a URL from the internet and extracts its contents as markdown.
    - `url` (string, required): URL to fetch
    - `max_length` (integer, optional): Maximum number of characters to return (default: 5000)
    - `start_index` (integer, optional): Start content from this character index (default: 0)
    - `raw` (boolean, optional): Get raw content without markdown conversion (default: false)
    
When the output type is 'md' and the fetched resource is a PDF, it will be automatically converted to plain text.

### Prompts

- **fetch**
  - Fetch a URL and extract its contents as markdown
  - Arguments:
    - `url` (string, required): URL to fetch

## Installation

Optionally: Install node.js, this will cause the fetch server to use a different HTML simplifier that is more robust.

### Using uv (recommended)

When using [`uv`](https://docs.astral.sh/uv/) no specific installation is needed. We will
use [`uvx`](https://docs.astral.sh/uv/guides/tools/) to directly run *mcp-server-fetch*.

### Using PIP

Alternatively you can install `mcp-server-fetch-tom` via pip:

```
pip install mcp-server-fetch-tom
```

After installation, you can run it as a script using:

```
mcp-server-fetch-tom
```

## Configuration

### Configure for Claude.app

Add to your Claude settings:

<details>
<summary>Using uvx</summary>

```json
{
  "mcpServers": {
    "fetch": {
      "command": "uvx",
      "args": ["--quiet", "mcp-server-fetch-tom"]
    }
  }
}
```
</details>

<details>
<summary>Using docker</summary>

```json
{
  "mcpServers": {
    "fetch": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "mcp/fetch"]
    }
  }
}
```
</details>

<details>
<summary>Using pip installation</summary>

```json
{
  "mcpServers": {
    "fetch": {
      "command": "mcp-server-fetch-tom"
    }
  }
}
```
</details>

### Configure for VS Code

For quick installation, use one of the one-click install buttons below...

[![Install with UV in VS Code](https://img.shields.io/badge/VS_Code-UV-0098FF?style=flat-square&logo=visualstudiocode&logoColor=white)](https://insiders.vscode.dev/redirect/mcp/install?name=fetch&config=%7B%22command%22%3A%22uvx%22%2C%22args%22%3A%5B%22--quiet%22%2C%22mcp-server-fetch-tom%22%5D%7D) [![Install with UV in VS Code Insiders](https://img.shields.io/badge/VS_Code_Insiders-UV-24bfa5?style=flat-square&logo=visualstudiocode&logoColor=white)](https://insiders.vscode.dev/redirect/mcp/install?name=fetch&config=%7B%22command%22%3A%22uvx%22%2C%22args%22%3A%5B%22--quiet%22%2C%22mcp-server-fetch-tom%22%5D%7D&quality=insiders)

[![Install with Docker in VS Code](https://img.shields.io/badge/VS_Code-Docker-0098FF?style=flat-square&logo=visualstudiocode&logoColor=white)](https://insiders.vscode.dev/redirect/mcp/install?name=fetch&config=%7B%22command%22%3A%22docker%22%2C%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22mcp%2Ffetch%22%5D%7D) [![Install with Docker in VS Code Insiders](https://img.shields.io/badge/VS_Code_Insiders-Docker-24bfa5?style=flat-square&logo=visualstudiocode&logoColor=white)](https://insiders.vscode.dev/redirect/mcp/install?name=fetch&config=%7B%22command%22%3A%22docker%22%2C%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22mcp%2Ffetch%22%5D%7D&quality=insiders)

For manual installation, add the following JSON block to your User Settings (JSON) file in VS Code. You can do this by pressing `Ctrl + Shift + P` and typing `Preferences: Open User Settings (JSON)`.

Optionally, you can add it to a file called `.vscode/mcp.json` in your workspace. This will allow you to share the configuration with others.

> Note that the `mcp` key is needed when using the `mcp.json` file.

<details>
<summary>Using uvx</summary>

```json
{
  "mcp": {
    "servers": {
      "fetch": {
        "command": "uvx",
        "args": ["--quiet", "mcp-server-fetch-tom"]
      }
    }
  }
}
```
</details>

<details>
<summary>Using Docker</summary>

```json
{
  "mcp": {
    "servers": {
      "fetch": {
        "command": "docker",
        "args": ["run", "-i", "--rm", "mcp/fetch"]
      }
    }
  }
}
```
</details>

### Customization - robots.txt

By default, the server will obey a websites robots.txt file if the request came from the model (via a tool), but not if
the request was user initiated (via a prompt). This can be disabled by adding the argument `--ignore-robots-txt` to the
`args` list in the configuration.

### Customization - User-agent

By default, depending on if the request came from the model (via a tool), or was user initiated (via a prompt), the
server will use either the user-agent
```
ModelContextProtocol/1.0 (Autonomous; +https://github.com/modelcontextprotocol/servers)
```
or
```
ModelContextProtocol/1.0 (User-Specified; +https://github.com/modelcontextprotocol/servers)
```

This can be customized by adding the argument `--user-agent=YourUserAgent` to the `args` list in the configuration.

### Customization - Proxy

The server can be configured to use a proxy by using the `--proxy-url` argument.

## Windows Configuration

If you're experiencing timeout issues on Windows, you may need to set the `PYTHONIOENCODING` environment variable to ensure proper character encoding:

<details>
<summary>Windows configuration (uvx)</summary>

```json
{
  "mcpServers": {
    "fetch": {
      "command": "uvx",
      "args": ["mcp-server-fetch-tom"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```
</details>

<details>
<summary>Windows configuration (pip)</summary>

```json
{
  "mcpServers": {
    "fetch": {
      "command": "mcp-server-fetch-tom",
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```
</details>

This addresses character encoding issues that can cause the server to timeout on Windows systems.

## Debugging

You can use the MCP inspector to debug the server. For uvx installations:

```
npx @modelcontextprotocol/inspector uvx mcp-server-fetch-tom
```

Or if you've installed the package in a specific directory or are developing on it:

```
cd path/to/fetch_mcp
npx @modelcontextprotocol/inspector uv run mcp-server-fetch-tom
```

## Contributing

We encourage contributions to help expand and improve mcp-server-fetch. Whether you want to add new tools, enhance existing functionality, or improve documentation, your input is valuable.

For examples of other MCP servers and implementation patterns, see:
https://github.com/modelcontextprotocol/servers

Pull requests are welcome! Feel free to contribute new ideas, bug fixes, or enhancements to make mcp-server-fetch even more powerful and useful.

## Security Considerations

While this server implements prompt injection safeguards, security is a shared responsibility:

1. **Defense in depth**: These safeguards are one layer of protection; combine with other security measures
2. **Regular updates**: Keep the server updated to benefit from new pattern detection rules
3. **Report vulnerabilities**: If you discover a bypass or vulnerability, please report it responsibly
4. **False positives**: The pattern detection may flag legitimate content; review warnings in context

## License

mcp-server-fetch is licensed under the MIT License. This means you are free to use, modify, and distribute the software, subject to the terms and conditions of the MIT License. For more details, please see the LICENSE file in the project repository.
