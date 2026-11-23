"""Plain-language meaning of every tag used in the row specifications. Used by make_prompt.py and docs/ROW_FORMAT.md.

Run `python tools/vocab.py` to print the tables as Markdown.
"""

CWE_NAME = {"CWE-89": "SQL injection", "CWE-78": "OS command injection", "CWE-22": "path traversal", "CWE-338": "use of a weak random number generator for a security value"}
LANG_NAME = {"python": "Python", "c": "C", "cpp": "C++", "go": "Go"}

CASE = {
    "normal": "plainly vulnerable",
    "hard_positive": "vulnerable even though it looks protected (the protection does not work)",
    "safe": "safe, written the standard way",
    "hard_negative": "completely safe, even though it uses the dangerous operation or looks like the vulnerable form",
    "no_code": "ordinary code from the same kind of program, with no dangerous operation for this weakness",
}

PATTERN = {
    "plain_vulnerable": "the most direct vulnerable form",
    "standard_safe": "the usual safe way to do this task",
    "no_dangerous_call": "no database, shell, file or random call for this weakness",
    # CWE-89 hard negatives
    "allow_listed_identifier": "a table or column name is chosen from a fixed allow-list before being put in the query; values are bound",
    "generated_placeholders": "the right number of placeholders is generated for a list of values, and the values are bound",
    "constant_fragments_only": "the query is assembled only from constant strings in the code",
    "query_builder_bound": "an ORM or query builder binds all values",
    "integer_forced": "the input is converted to an integer before it is used in the query",
    "fstring_placeholders_only": "a formatted string is used, but it only inserts placeholders or constants; values are bound",
    # CWE-89 hard positives
    "hand_written_escaping": "the code escapes quotes by hand, which can be bypassed",
    "keyword_blocklist": "the code rejects some SQL keywords or characters, but other payloads still work",
    "param_in_one_branch_only": "one branch binds parameters, another branch builds the query from input",
    "identifier_from_input": "values are bound, but a table or sort column comes straight from input",
    "second_order_stored_value": "a value read back from the database is trusted and put into a new query",
    # CWE-78 hard negatives
    "constant_shell_command": "a shell is used, but the command is completely constant",
    "all_args_quoted": "a shell is used and every input value is properly quoted for that shell",
    "argv_list_user_data": "the program is run with an argument list and no shell; user data is one argument",
    "command_from_fixed_map": "the command is picked from a fixed table by a key",
    "strict_parser_no_shell": "input is checked by a strict parser (for example an IP address parser) and passed without a shell",
    "end_of_options_marker": "user data is passed after an end-of-options marker such as --, without a shell",
    # CWE-78 hard positives
    "partial_metachar_filter": "the code rejects some shell characters, but others still work",
    "quoting_wrong_context": "the value is quoted, but in a way the shell still breaks out of",
    "validates_other_variable": "the check is done on a different variable from the one used in the command",
    "validator_too_permissive": "the validator accepts more than it appears to",
    "argument_injection_dash": "no shell, but a value starting with a dash is read as an option",
    # CWE-22 hard negatives
    "resolve_then_contain_with_separator": "the path is resolved, then checked to be inside the base folder with a separator-aware test",
    "basename_only": "only the last name component of the input is used",
    "id_mapped_to_known_file": "an identifier is mapped to a known file name from a table",
    "safe_filename_fixed_folder": "a safe-filename helper cleans the name and a fixed folder is used",
    "library_confined_access": "a library call that confines access to one folder is used",
    "allow_listed_name": "the name must be one of a fixed list",
    # CWE-22 hard positives
    "check_before_normalise": "the check is done before the path is normalised",
    "prefix_without_separator": "a prefix test without a path separator lets a sibling folder through",
    "single_pass_dotdot_strip": "'../' is removed only once, so nested sequences survive",
    "misses_absolute_path": "the check catches '..' but not absolute paths",
    "extension_check_only": "only the file extension is checked",
    # CWE-338 hard negatives
    "non_security_simulation": "ordinary random is used for a simulation or game, not for security",
    "non_security_shuffle_or_sample": "ordinary random shuffles or samples data, not for security",
    "retry_jitter": "ordinary random adds jitter to a delay",
    "fixed_seed_experiment": "a fixed seed is used on purpose for a reproducible experiment",
    "secure_secret_random_elsewhere": "the secret comes from a secure generator; ordinary random is used elsewhere in the function for something harmless",
    "game_or_ui_randomness": "ordinary random picks a colour, message or similar for display",
    # CWE-338 hard positives
    "weak_generator_in_helper": "the secret comes from a helper that uses ordinary random",
    "secure_sounding_name": "a function or variable name suggests security, but ordinary random is used",
    "seeded_from_clock": "the generator is seeded from the time or the process id",
    "weak_value_hashed": "a weak random value is hashed, which does not make it unpredictable",
    "secure_seed_for_weak_generator": "a secure value is only used as the seed of an ordinary generator",
}

FIX = {
    "parameterised_query": "use bound parameters instead of building the query text",
    "allow_list": "accept only allowed values: a fixed list of values, or only allowed characters",
    "type_conversion": "convert the input to the expected type (for example an integer) before use",
    "query_builder_orm": "use the ORM or query builder so values are bound",
    "argv_no_shell": "run the program with an argument list and no shell",
    "quote_escape": "quote every value correctly for the shell",
    "validate_format": "accept only input that matches a strict format",
    "end_of_options": "pass user data after an end-of-options marker and without a shell",
    "normalize_prefix_check": "resolve the path and check it stays inside the base folder",
    "basename_only": "use only the last name component",
    "safe_join_library": "use a library function that joins safely inside a folder",
    "id_to_file_map": "map an identifier to a known file instead of using the name",
    "secrets_module": "use Python's secrets module",
    "system_random": "use random.SystemRandom",
    "os_urandom": "use os.urandom",
    "os_random_api": "use the operating system's secure random call (getrandom or getentropy)",
    "dev_urandom": "read bytes from /dev/urandom",
    "csprng_library": "use a cryptographic library's random function (for example libsodium randombytes_buf or OpenSSL RAND_bytes)",
    "crypto_rand_read": "use crypto/rand.Read",
    "crypto_rand_int": "use crypto/rand.Int",
    "crypto_rand_text": "use crypto/rand.Text or crypto/rand with an encoding",
}

SHAPE = {
    "plain_function": "a plain function",
    "method": "a method of a class (C: a function taking a context struct; C++: a member function; Go: a method on a struct type)",
    "web_handler": "a web or network request handler",
    "cli_entry": "the main work of a command-line tool, taking its arguments",
    "helper_called_by_caller": "a helper function plus the short function that calls it",
    "callback_or_async": "an asynchronous function or a callback",
}
SHAPE_BY_LANG = {"method": {"python": "a method of a class", "c": "a function that takes a context struct", "cpp": "a member function of a class",
                            "go": "a method on a struct type"}}
VALUE = {"token": "token", "otp": "one-time code", "password": "password", "session": "session identifier", "salt": "salt", "key": "secret key"}

SOURCE = {
    "function_argument": "a function argument",
    "web_request": "a web request (query string, form field, JSON body, URL path)",
    "file_content": "the content of a file",
    "environment": "an environment variable",
    "command_line": "a command-line argument",
    "database_value": "a value read from a database",
    "network_message": "a message received over the network",
    "not_applicable": "no untrusted input",
}


if __name__ == "__main__":
    for title, d in (("Case types", CASE), ("Patterns", PATTERN), ("Fix types", FIX), ("Shapes", SHAPE), ("Input sources", SOURCE)):
        print(f"\n### {title}\n\n| Tag | Meaning |\n|---|---|")
        for k, v in d.items():
            print(f"| `{k}` | {v} |")
