# Security model

GeminiRDC runs as the Windows user who starts it. The HTTPS proxy communicates with the loopback MCP port. OAuth access is scoped to the bridge's resource URL. OAuth state is encrypted with Windows DPAPI for the current user.

New enrollment starts closed. The PC owner opens a 15-minute window and approves the request ID shown during Google OAuth linking. Closing enrollment leaves existing valid links usable. A valid OAuth client can read the dedicated workspace, basic hardware details, and process names and IDs.

Mutating file operations, commands, and screenshots require a separate review on the PC. The approval page listens on a separate loopback port. Keep that port off the reverse proxy. PowerShell starts in the workspace directory with the Windows user's permissions and can access resources elsewhere if the approved command asks for them. Run the bridge from a standard account and review the exact command.

To revoke access, disconnect in Gemini. A full local reset stops the bridge, removes its own `.bridge\oauth.dpapi` file, and restarts it. Restarting also clears pending operations and their results.

Report suspected vulnerabilities through the repository's **Security → Report a vulnerability** form. Include a minimal reproduction with synthetic data and redact tokens, public endpoint addresses, and personal files.
