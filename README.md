# cvs-PolyglotCodeSynthesizer
Creates polyglot code snippets that are intentionally vulnerable across multiple languages or interpreters. Uses a combination of language-specific parsing libraries and code templates to generate snippets that exhibit different vulnerabilities depending on the interpreter used. Example: a snippet vulnerable to XSS in a browser but SQL injection in a backend database query. - Focused on Tools designed to automatically generate vulnerable code snippets based on common vulnerability patterns (e.g., SQL injection, XSS, command injection). This facilitates training and testing of security scanners and code analysis tools, as well as enabling developers to understand and avoid specific vulnerabilities.

## Install
`git clone https://github.com/ShadowStrikeHQ/cvs-polyglotcodesynthesizer`

## Usage
`./cvs-polyglotcodesynthesizer [params]`

## Parameters
- `-h`: Show help message and exit
- `--vulnerability`: No description provided
- `--languages`: The target languages/interpreters for the polyglot snippet.
- `--length`: No description provided
- `--output_file`: The file to write the generated code snippet to. If not specified, a random filename is generated in the output directory.
- `--offensive`: Generate snippet suitable for direct execution (more 

## License
Copyright (c) ShadowStrikeHQ
