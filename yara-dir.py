import yara
import sys
import os
import click
import colorama
from colorama import Fore, Style

global printStrings


def checkMatches(rule, directory):
    global printStrings
    compRule = yara.compile(rule)

    matches = []
    counter = 0
    total = 0

    for file in os.listdir(directory):
        file_dir = os.path.join(directory, file)
        if '.py' not in str(file) and os.path.isfile(file_dir):

            total += 1
            match = compRule.match(file_dir)

            if len(match) >= 1:
                if printStrings:

                    tmp = [file + " rule Hits == " + str(match), match]
                    matches.append(tmp)
                    counter += 1
                else:
                    matches.append(file + " rules=" + str(match))
                    counter += 1

    if printStrings:
        for file in matches:
            print(f'{Fore.RED}{file[0]}{Style.RESET_ALL}' )
            for rule in file[1]:
                name = rule.rule
                print(f'{Fore.GREEN}-------- :Rule: {name} --------{Style.RESET_ALL}')
                for string_hits in rule.strings:
                    offset = string_hits[0]
                    identifer = string_hits[1]
                    data = string_hits[2]
                    print(f'offset:{hex(offset)}\nidentifier:{identifer}\ndata:{data}\n')
                print(f'{Fore.GREEN}-------- :End Of Rule Strings: --------{Style.RESET_ALL}\n')
    else:
        for m in matches:
            print(m)
    print(f'Hits for rule {counter}/{total}')


def checkUnMatches(rule, directory):
    compRule = yara.compile(rule)
    matches = []
    counter = 0
    total = 0

    for file in os.listdir(directory):
        try:
            total += 1
            if len(compRule.match(directory + file)) < 1:
                matches.append(file)
                counter += 1
        except Exception as e:
            print(f'Caught exception {e}')
            continue

    for f in matches:
        print(f)
    print(f"Files not matched : {counter}/{total}")


def Diff(li1, li2):
    return list(list(set(li1) - set(li2)) + list(set(li2) - set(li1)))


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.command(context_settings=CONTEXT_SETTINGS)
@click.argument('rule', type=click.Path(exists=True), required=True)
@click.argument('directory', type=click.Path(exists=True), required=True)
@click.option('-m', 'match', is_flag=True, default=False, help="Prints every match for rule in directory")
@click.option('-n', 'notMatch', is_flag=True, default=False, help='Prints every file not matched for rule in directory')
@click.option('-s', 'printStringMatch', is_flag=True, default=False, help='Prints String matches for files')
def main(rule, directory, match, notMatch, printStringMatch):
    global printStrings
    printStrings = printStringMatch

    # Cheap check for directory path if missing trailing path separator
    directory = os.path.join(directory, "")

    if not match and not notMatch:
        raise SyntaxError('Specify and options')

    if not os.path.isfile(rule):
        raise SyntaxError(f'{rule} is not a file')

    if match:
        checkMatches(rule, directory)
    else:
        checkUnMatches(rule, directory)


if __name__ == "__main__":
    main()
