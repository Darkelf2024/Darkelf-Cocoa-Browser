"""
Darkelf Cocoa Browser launcher
"""

import sys


def run():
    try:
        # import the browser module
        from . import browser

        # if your script has a main() function
        if hasattr(browser, "main"):
            browser.main()

        else:
            print("Darkelf browser module loaded, but no main() function found.")

    except Exception as e:
        print("Darkelf failed to start:")
        print(e)
        sys.exit(1)


if __name__ == "__main__":
    run()
