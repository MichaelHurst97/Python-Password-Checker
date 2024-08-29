"""PwnedCheck: Set of functions to check if a given string or multiple strings
in a file are in Troy Hunt's "Have I Been Pwned" database,
returns the results as Boolean.
"""


# Import modules
import hashlib

try:
    import requests
except ModuleNotFoundError:
    print("use: pipenv install requests")
    raise


def hash_password_sha1(password_cleartext):
    """Generate and return a SHA-1 hash string out of a given string.
    """

    try:
        # Encode a string as Unicode UTF-8 as bytes should be hashed
        password_hashed = hashlib.sha1(
            password_cleartext.encode(encoding="UTF-8"))

        # Return the hash as a string object containing only
        # hexadecimal digits in upper case
        return password_hashed.hexdigest().upper()

    except AttributeError:

        if type(password_cleartext) is int:
            password_casted = str(password_cleartext)
            password_hashed = hashlib.sha1(
                password_casted.encode(encoding="UTF-8"))
            return password_hashed.hexdigest().upper()
        
        else:
            print("Error: Wrong input type, try string")
            raise


def return_hashlist_hibp(password_hash):
    """Return a list of SHA-1 hashes from HIBP's database \
that contain the first five digits of a given SHA-1 hash
    """

    # Chop off the first five digits of the given hash
    password_hash_chop = password_hash[:5]
    try:
        # Request the list and return it
        password_list_requested = requests.get(
                "https://api.pwnedpasswords.com/range/{}".format(
                    password_hash_chop))

        if not password_list_requested.ok:
            raise RuntimeError(
                "Connection error fetching hash list with code {}".format(
                    password_list_requested.status_code))
        return password_list_requested.text

    except ConnectionError:
        print("Error: No connection to the HIPB Server. \
Please check your internet connection.")
        raise


def check_status(password_cleartext):
    """Check if a single string can be found in the HIPB database. \
Return only the pwned status of the string as bool.
    """
    try:
        # Get a list of password hashes containing the first five
        # hashed digits of the input password
        password_list_potential = return_hashlist_hibp(
            hash_password_sha1(password_cleartext))

        # Go through each line in the hash list and return if
        # our password hash exists
        for line in password_list_potential.splitlines():
            simplified_hash = line.split(":")

            if simplified_hash[0] == hash_password_sha1(
                password_cleartext)[5:]:
                return True
        return False

    except AttributeError:
        print("Error Wrong input type. Try String.")
        raise


def check_list(list_path):
    """Go through a list of strings and check each against HIBP's database. \
Return a dict with these strings and their pwned status as bool.
    """

    # Read the contents of a file
    try:
        with open(list_path, "r") as file_object:
            list_lines = file_object.read().splitlines()

        # Go through each list list index and check it with check_status
        returned_bool_list = []
        for i in range(len(list_lines)):
            returned_bool_list.append(check_status(list_lines[i]))

        # Create a dictionary out of cleartext passwords and
        # their pwned status
        compose_dict = dict(zip(list_lines, returned_bool_list))

        return compose_dict

    except FileNotFoundError:
        print("Error: File not found! Check path and spelling.")
        raise