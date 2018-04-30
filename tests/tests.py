from servertests import FlaskTestCase
from cryptotests import CryptoTestCases
import unittest


if __name__ == '__main__':
    flaskTests = unittest.TestLoader().loadTestsFromTestCase(FlaskTestCase)
    cryptoTests = unittest.TestLoader().loadTestsFromTestCase(CryptoTestCases)
    #Select tests to run
    unittest.TextTestRunner(verbosity=2).run(flaskTests)
    #unittest.TextTestRunner(verbosity=2).run(cryptoTests)


