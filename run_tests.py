import sys
import os
sys.path.insert(0, os.path.abspath("dependencies"))

import tests.test_dsa
import tests.test_ecdsa
import tests.test_ecelgamal
import tests.test_elgamal
from colorama import Fore, Style, init

init(autoreset=True)

def run_tests():
    sections = {
        "DSA": tests.test_dsa,
        "ECDSA": tests.test_ecdsa,
        "El Gamal": tests.test_elgamal,
        "EC El Gamal": tests.test_ecelgamal
    }

    def format_result(success, test_name, error=None):
        status = f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL}" if success else f"{Fore.RED}[FAILED]{Style.RESET_ALL}"
        border = f"{Fore.CYAN}{'=' * (len(test_name) + 10)}{Style.RESET_ALL}"
        print(f"\n{border}\n{status} {Fore.WHITE}{test_name}{Style.RESET_ALL}\n{border}")
        if error:
            print(f"{Fore.YELLOW}Error: {error}{Style.RESET_ALL}\n")

    for name, module in sections.items():
        print(f"\n{Fore.CYAN}===== Running {name} Tests ====={Style.RESET_ALL}")
        for test in dir(module):
            if test.startswith("test_"):
                try:
                    getattr(module, test)()
                    format_result(True, test)
                except Exception as e:
                    format_result(False, test, e)

    print(f"\n{Fore.GREEN}🚀 All tests completed!{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}If you are seeing this, then all tests were successful!{Style.RESET_ALL}")

if __name__ == "__main__":
    run_tests()
