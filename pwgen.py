"""PWGen: Very simple random password generator.
"""


# Import modules
import secrets
import string


def generate_password(password_length):
    if isinstance(password_length, int) is False:
        print("Error: Given input is not int. Try again.")
        return None

    elif password_length > 0:

        # Create a string containing letters, digits and punctuation,
        # cycle through it and pick random ones
        gen_characters = (string.ascii_letters +
                            string.digits + string.punctuation)

        password_generated = "".join(secrets.choice(gen_characters)
                                    for i in range(password_length))
        return password_generated

    elif password_length <= 0:
        print("Error: Length of to be generated \
password can't be 0 or smaller than 0. Try again.")
        return None
    
    else:
        return None