import argparse
import logging
import sys
import os
import secrets
import string
import subprocess
import shlex

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
OUTPUT_DIR = "output"
DEFAULT_SNIPPET_LENGTH = 20  # In characters

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(
        description="cvs-PolyglotCodeSynthesizer: Generates polyglot code snippets with vulnerabilities."
    )

    parser.add_argument(
        "--vulnerability",
        type=str,
        choices=["xss", "sql_injection", "command_injection"],
        required=True,
        help="The type of vulnerability to introduce (xss, sql_injection, command_injection).",
    )

    parser.add_argument(
        "--languages",
        type=str,
        nargs="+",
        required=True,
        help="The target languages/interpreters for the polyglot snippet.",
    )

    parser.add_argument(
        "--length",
        type=int,
        default=DEFAULT_SNIPPET_LENGTH,
        help=f"The approximate length of the generated code snippet (default: {DEFAULT_SNIPPET_LENGTH}).",
    )

    parser.add_argument(
        "--output_file",
        type=str,
        help="The file to write the generated code snippet to. If not specified, a random filename is generated in the output directory.",
    )

    parser.add_argument(
        "--offensive",
        action="store_true",
        help="Generate snippet suitable for direct execution (more 'offensive'). Requires extra caution.",
    )

    return parser


def generate_random_string(length):
    """
    Generates a random string of the specified length.

    Args:
        length (int): The length of the string to generate.

    Returns:
        str: A random string.
    """
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_xss_snippet(length, offensive=False):
    """
    Generates an XSS vulnerable code snippet.

    Args:
        length (int): The approximate length of the snippet.
        offensive (bool):  Whether to generate an 'offensive' version

    Returns:
        str: The generated XSS snippet.
    """
    logging.info("Generating XSS snippet.")

    if offensive:
        # More aggressive/obvious XSS
        snippet = f"<script>alert('{generate_random_string(length // 2)}');</script>"
    else:
        # More subtle XSS, relying on attribute injection
        snippet = f"<img src='#' onerror='alert(\"{generate_random_string(length // 2)}\")'>"

    return snippet


def generate_sql_injection_snippet(length, offensive=False):
    """
    Generates a SQL injection vulnerable code snippet.

    Args:
        length (int): The approximate length of the snippet.
        offensive (bool): Whether to generate an 'offensive' version.

    Returns:
        str: The generated SQL injection snippet.
    """
    logging.info("Generating SQL injection snippet.")

    if offensive:
        # More straightforward SQL injection
        snippet = f"'; DROP TABLE users; --"
    else:
        # SQL injection with string concatenation
        random_value = generate_random_string(length // 4)
        snippet = f"' OR '{random_value}'='{random_value}"  # Always true condition

    return snippet


def generate_command_injection_snippet(length, offensive=False):
    """
    Generates a command injection vulnerable code snippet.

    Args:
        length (int): The approximate length of the snippet.
        offensive (bool): Whether to generate an 'offensive' version.

    Returns:
        str: The generated command injection snippet.
    """
    logging.info("Generating command injection snippet.")
    if offensive:
        # Directly execute shell command
        snippet = f"`touch /tmp/{generate_random_string(5)}`"
    else:
         # Command injection with semicolon
        snippet = f"; echo {generate_random_string(length // 4)};"


    return snippet


def generate_snippet(vulnerability, length, offensive=False):
    """
    Generates a vulnerable code snippet based on the specified vulnerability type.

    Args:
        vulnerability (str): The type of vulnerability (xss, sql_injection, command_injection).
        length (int): The approximate length of the snippet.
        offensive (bool): Whether to generate an 'offensive' version.

    Returns:
        str: The generated code snippet, or None if the vulnerability type is invalid.
    """
    if vulnerability == "xss":
        return generate_xss_snippet(length, offensive)
    elif vulnerability == "sql_injection":
        return generate_sql_injection_snippet(length, offensive)
    elif vulnerability == "command_injection":
        return generate_command_injection_snippet(length, offensive)
    else:
        logging.error(f"Invalid vulnerability type: {vulnerability}")
        return None


def write_snippet_to_file(snippet, output_file):
    """
    Writes the generated code snippet to the specified file.

    Args:
        snippet (str): The code snippet to write.
        output_file (str): The path to the output file.

    Returns:
        None
    """
    try:
        with open(output_file, "w") as f:
            f.write(snippet)
        logging.info(f"Snippet written to: {output_file}")
    except Exception as e:
        logging.error(f"Error writing to file: {e}")


def validate_languages(languages):
    """
    Placeholder for language validation.  In a real application,
    this would check if the languages are supported or valid.
    """
    #Add your Language validation logic here.
    return True

def main():
    """
    Main function to parse arguments, generate the code snippet, and write it to a file.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Validate inputs
    if not isinstance(args.length, int) or args.length <= 0:
        logging.error("Length must be a positive integer.")
        sys.exit(1)

    if not validate_languages(args.languages):
        logging.error("Invalid languages specified.")
        sys.exit(1)

    # Generate the code snippet
    snippet = generate_snippet(args.vulnerability, args.length, args.offensive)

    if snippet is None:
        sys.exit(1)

    # Determine the output file path
    if args.output_file:
        output_file = args.output_file
    else:
        # Ensure the output directory exists
        if not os.path.exists(OUTPUT_DIR):
            try:
                os.makedirs(OUTPUT_DIR)
            except OSError as e:
                logging.error(f"Error creating output directory: {e}")
                sys.exit(1)
        output_file = os.path.join(OUTPUT_DIR, f"vulnerable_snippet_{generate_random_string(8)}.txt")

    # Write the snippet to a file
    write_snippet_to_file(snippet, output_file)

    logging.info("Finished.")


if __name__ == "__main__":
    main()