from servertests import FlaskTestCase
from cryptotests import CryptoTestCases
import unittest

def suite(classes, unit_tests_to_run):
    """
        Problem with sys.argv[1] when unittest module is in a script
        https://stackoverflow.com/questions/2812218/problem-with-sys-argv1-when-unittest-module-is-in-a-script

        Is there a way to loop through and execute all of the functions in a Python class?
        https://stackoverflow.com/questions/2597827/is-there-a-way-to-loop-through-and-execute-all-of-the-functions

        looping over all member variables of a class in python
        https://stackoverflow.com/questions/1398022/looping-over-all-member-variables-of-a-class-in-python
    """
    suite = unittest.TestSuite()
    unit_tests_to_run_count = len( unit_tests_to_run )

    for _class in classes:
        _object = _class()

        for function_name in dir( _object ):

            if function_name.lower().startswith( "test" ):

                if unit_tests_to_run_count > 0 \
                        and function_name not in unit_tests_to_run:

                    continue

                suite.addTest( _class( function_name ) )

    return suite


if __name__ == '__main__':
    flaskTests = unittest.TestLoader().loadTestsFromTestCase(FlaskTestCase)
    cryptoTests = unittest.TestLoader().loadTestsFromTestCase(CryptoTestCases)
    #Select tests to run
    #unittest.TextTestRunner(verbosity=2).run(flaskTests)
    #unittest.TextTestRunner(verbosity=2).run(cryptoTests)
    runner = unittest.TextTestRunner();
    runner.run(suite([FlaskTestCase],["test_23_client"]));



