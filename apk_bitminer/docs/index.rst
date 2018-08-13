Welcome to apk_bitminer's User Guide!
================================

apk_bitminer is a python utility and library used to extract information from and Android apk file.  The 
tool is based off of similar work in Kotlin in the found here https://github.com/linkedin/dex-test-parser, 
authored by Drew Hannay.  Specifically, the
tool can parse the dex files within an apk to determine the list of tests present within the apk (for test
apks).  The tool can also extract the binary-formatted AndroidManifest.xml file back into a human-readable form.

.. toctree::
   :maxdepth: 2

Extracting Test Information
===========================

To list the tests contained in an apk file from the command line:

.. code-block:: bash

    % pydexdump <apk-file>

Via the api:

.. code-block:: python

    from apk_bitminer.parsing import DexParser

    # print all tests in an apk, but only those in package 'filter.on.package'
    for test in DexParser.parse("/path/to/some.apk", pacakge_names=["filer.on.package'])
        print(test)

Note that package_names can be a filename-like wildcard expression contain "*", "[]" or "?", or a regular expression.
Regular expressions are passed in with the prefix "re::", for example "re::filter\.on\.pack[age]*".

Extracting AndroidManifest.xml
==============================

To print the AndroidMainfiest.xml in an apk file in human-readable form from the command line:

.. code-block:: bash

    % axmldump <apk-file>

Via the api:

.. code-block:: python

    from apk_bitminer.parsing import AXMLParser

    #print the XML of the AXML manifest file in an apk:
    parser = AXMLParser.parse("/path/to/some.aok")
    print(parser.xml)


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
