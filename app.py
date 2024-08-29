#!/usr/bin/env python3

"""PwnedWord: Password Checker using Troy Hunt's "Have I Been Pwned" service

Use -t to check for a single password.
e.g.: pwnedword.py -t 123456

Use -f to import a file containing passwords.
Input path, filename and file extension.
e.g.: pwnedword.py -f /home/user/Documents/pwlist.txt

Use -g to generate a random password and check it against the HIBP service.
e.g.: pwnedword.py -g 10

Use -v to turn the display of cleartext passwords on or off. Default is off.
"""


# Import modules
import argparse
import pwnedcheck
import pwgen


# Class setup so others can create instances of it with e.g. different pws
class PwnedWord():
    """Class to check and generate passwords using included
    pwnedcheck and pwgen modules.

    Args:
        password_string (str): String to be checked.
        password_file_string (str): File to be checked, each line is one
                                    password. Path and filename must be a
                                    string.
        password_gen_length (int): Length of a to be generated and
                                    checked password
        password_verbose (bool): Toggles verbose output. Default is false.

    Returns:
        None.
    """

    def __init__(self,
                password_string,
                password_file_string,
                password_gen_length,
                password_verbose):

        # Dict with all results
        # But gets attributes from each verbosity level added
        self.dict_records = {}

        # If -t input is given, check for verbose output, then output
        # pwned result. pwnedcheck Module handles exception and error output.
        if password_string is not None:

            password_status = pwnedcheck.check_status(password_string)

            if password_verbose is True:
                print("Has password {} been pwned? {}".format(
                    password_string, password_status))

                # Assign values to instance value and dict_records
                self.password_string = password_string
                self.password_status = password_status
                self.dict_records.update({password_string: password_status})

            if password_verbose is False:
                print("Has your password been pwned? {}".format(
                    password_status))

                self.password_status = password_status
                self.dict_records.update({"Password Status": password_status})

        # If -f file path is given
        if password_file_string is not None:

            # Create a new list so server request is only made once
            return_dict = pwnedcheck.check_list(password_file_string)

            # Verbose On. Iterate through the dicts keys(pws) and
            # values(status) and output password and its status
            # None as return means error. -> skip
            if password_verbose is True and return_dict is not None:
                for k, v in return_dict.items():
                    print("Has password {} been pwned? {}"
                        .format(k, v))

                    self.return_dict = return_dict.items()
                    self.dict_records.update(return_dict.items())

            # Verbose off
            if password_verbose is False and return_dict is not None:

                # Build new dict out of index and bool lists for later output,
                # "for k, v" so enum values and the actual pw get split
                # then only append the stuff we want (not the pw)
                return_dict_index = []
                return_dict_bools = []
                for k, v in enumerate(return_dict, 1):
                    return_dict_index.append(k)

                for k, v in return_dict.items():
                    return_dict_bools.append(v)

                return_dict_stripped = dict(zip(return_dict_index,
                                                return_dict_bools))

                # Now comes the actual output
                for k, v in return_dict_stripped.items():
                    print("Has password {} in list been pwned? {}"
                        .format(k, v))

                    self.return_dict_stripped = return_dict_stripped.items()
                    self.dict_records.update(return_dict_stripped.items())

        # If -g argument is given
        if password_gen_length is not None:

            # Generate a password then get its pwned status
            password_gen = pwgen.generate_password(password_gen_length)
            password_gen_status = pwnedcheck.check_status(password_gen)

            # Check if generated password has been pwned yet,
            # if so generate a new one and repeat
            while password_gen_status is True:
                print("Generated password {} is already pwned. Trying again."
                    .format(password_gen))
                password_gen = pwgen.generate_password(password_gen_length)
                password_gen_status = pwnedcheck.check_status(password_gen)

            # Output a password that has made it till here
            # (aka password_gen _status equals false)
            # None returned as password_gen _status means error. -> skip!
            if password_gen_status is not None:
                print("The generated password is {} and it has not been \
pwned yet.".format(password_gen))

                self.password_gen = password_gen
                self.password_gen_status = password_gen_status
                self.dict_records.update({password_gen: password_gen_status})


# Part that can actually get input from the user
# Initialize command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-t", "--text",
                    type=str, required=False,
                    help="Password to be checked.")
parser.add_argument("-f", "--file",
                    type=str, required=False,
                    help="File to be checked.")
parser.add_argument("-g", "--gen",
                    type=int, required=False, metavar="LENGTH",
                    help="Generates and checks a password of given length.")
# Default verbose setting is False aka off!
parser.add_argument("-v", "--verbose",
                    action="store_true", required=False,
                    help="Turn display of cleartext password on or off. \
                    Default is off.")

args = parser.parse_args()


# Create a PwnedWord instance and give it the cli arguments
# It will then check which args exist and perform corresponding actions
runArgs = PwnedWord(args.text, args.file, args.gen, args.verbose)

# Running it from inside python could look like this:
# runInside = PwnedWord("Hello World", None, myNumber, True)
# myCoolPassword = runInside.password_gen
# print(runInside.dict_records)

# Print instructions if no arguments are given
if args.text is None and \
    args.file is None and \
    args.gen is None:
    print(__doc__)